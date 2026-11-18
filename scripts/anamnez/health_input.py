"""Read a collector snapshot and track what evidence is available."""

from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from evtx_read import event_details, records


def local_path(name):
    parts = name.split('/')
    if any(part in ('', '.', '..') or any(c in part for c in '\\:\r\n\0') for part in parts):
        raise ValueError('Invalid path in capture')
    return PurePosixPath(*parts)


@contextmanager
def capture_folder(source):
    if source.is_dir():
        yield source
        return
    if not source.is_file() or source.suffix.lower() != '.7z':
        raise ValueError('Choose a capture folder or a .7z archive')
    seven_zip = shutil.which('7z') or shutil.which('7zz')
    if not seven_zip:
        raise ValueError('7-Zip is required for .7z input. Choose an unpacked capture folder instead.')
    source = source.resolve()

    def run(*args):
        try:
            result = subprocess.run([seven_zip, *args], capture_output=True, stdin=subprocess.DEVNULL,
                                    timeout=600, check=False)
        except subprocess.TimeoutExpired:
            raise ValueError('7-Zip timed out while reading the capture') from None
        if result.returncode:
            raise ValueError(f'7-Zip could not read the capture (exit {result.returncode})')
        return result.stdout.decode('utf-8')

    listing = run('l', '-t7z', '-slt', '-ba', '-sccUTF-8', str(source))
    members = {}
    for block in re.split(r'\r?\n\r?\n', listing.strip()):
        fields = {}
        for line in block.splitlines():
            key, sep, value = line.partition(' = ')
            if not sep or key in fields:
                raise ValueError('Invalid archive member listing')
            fields[key] = value
        member = local_path(fields.get('Path', '').replace('\\', '/'))
        key = str(member).casefold()
        attributes = fields.get('Attributes', '').split()
        if (key in members or fields.get('Symbolic Link') or fields.get('Hard Link')
                or any(re.fullmatch(r'l[\-rwxstST]{9}', attr) for attr in attributes)):
            raise ValueError('Archive contains duplicate paths or links')
        members[key] = member
    roots = {member.parts[0] for member in members.values()}
    if len(roots) != 1 or not any(len(member.parts) > 1 for member in members.values()):
        raise ValueError('Expected one capture folder inside the archive')
    with tempfile.TemporaryDirectory(prefix='anamnez-') as temp:
        run('x', '-t7z', '-y', '-bd', '-sccUTF-8', f'-o{temp}', str(source))
        root = Path(temp) / roots.pop()
        if not root.is_dir() or root.is_symlink() or any(path.is_symlink() for path in root.rglob('*')):
            raise ValueError('Archive did not contain a plain capture folder')
        yield root


def read_text(path):
    raw = path.read_bytes()
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        text = raw.decode('utf-16', errors='replace')
    else:
        try:
            text = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            text = raw.decode('cp866')
    return text.replace('\r\n', '\n')


def digest(path):
    sha = sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(chunk)
    return sha.hexdigest()


def utc(text):
    try:
        value = text.strip().replace('Z', '+00:00')
        # Windows timestamps can include seven fractional digits, while Python 3.8 accepts three or six.
        value = re.sub(r'\.(\d+)', lambda match: '.' + match[1][:6].ljust(6, '0'), value, count=1)
        result = datetime.fromisoformat(value)
        offset = result.utcoffset()
        return result.replace(tzinfo=None) - offset if offset is not None else result
    except (AttributeError, ValueError, OverflowError):
        return None


def timestamp(value):
    return value.isoformat(timespec='seconds') + 'Z' if value is not None else None


def source_state(count, issues, exists=True):
    if not exists:
        return 'missing'
    if issues:
        return 'partial' if count else 'unreadable'
    return 'readable' if count else 'empty'


class Capture:
    def __init__(self, root):
        self.root = root.resolve()
        self.sources = {}
        self.notes = []
        self.clock_notes = []
        self.bad_files = set()
        self.checked_files = set()
        self.integrity = self.verify_manifest()
        summary = self.text('00-summary.txt')
        self.journal = self.text('00-journal.txt')
        self.metadata = {}
        fields = ('Host', 'OS', 'Machine', 'CPU', 'RAM', 'Disk', 'Time zone', 'PowerShell', 'Dump mode', 'WER')
        for field in fields:
            values = re.findall(r'^' + re.escape(field) + r'[ \t]*:[ \t]*(.+)$', summary, re.M)
            if values:
                key = field.lower().replace(' ', '_')
                self.metadata[key] = values if field in ('Disk', 'CPU') else values[0].strip()
        if 'host' in self.metadata:
            self.metadata['host'] = re.split(r'\s+user:', self.metadata['host'], maxsplit=1)[0]
        failed = re.search(r'^Failed steps:[ \t]*(\d+)', summary, re.M)
        self.metadata['failed_steps'] = int(failed[1]) if failed else None
        self.metadata['collection_failures'] = [line.partition(' FAIL ')[2] for line in self.journal.splitlines()
                                                if ' FAIL ' in line]
        if not summary:
            self.notes.append('Collection summary is missing or unreadable')
        if (self.metadata['failed_steps'] or 0) or self.metadata['collection_failures']:
            self.notes.append('Some collection steps failed')

        collected = re.search(r'^anamnez\.ps1 - collected (.+)$', summary, re.M)
        zone = re.search(r'offset now ([+-]?)(\d\d):(\d\d)(?::(\d\d))?', self.metadata.get('time_zone', ''))
        local = utc(collected[1]) if collected else None
        self.collected = None
        self.metadata['collected_local'] = local.isoformat(timespec='seconds') if local is not None else None
        if local is not None and zone is not None:
            offset = timedelta(hours=int(zone[2]), minutes=int(zone[3]), seconds=int(zone[4] or 0))
            self.collected = local - offset if zone[1] != '-' else local + offset
        self.metadata['collected_utc'] = timestamp(self.collected)
        if '!! CLOCK' in summary or 'CLOCK IS WRONG' in self.journal or (local and local.year < 2005):
            self.clock_notes.append('The collector flagged the machine clock')

        self.log_counts = {}
        section = summary.partition('Event logs (records  channel):')[2].strip().split('\n\n', 1)[0]
        for count, channel in re.findall(r'^[ \t]*(\d+|\?)[ \t]+([^\r\n]+)$', section, re.M):
            self.log_counts[channel.strip()] = int(count) if count != '?' else None

    def file(self, relative):
        file = self.root / relative
        if any(part.is_symlink() for part in (file, *file.parents) if part != self.root and self.root in part.parents):
            raise ValueError('Links are not supported inside a capture')
        return file

    def text(self, relative):
        if relative in self.bad_files:
            return ''
        try:
            return read_text(self.file(relative))
        except (OSError, ValueError):
            return ''

    def verify_manifest(self):
        manifest = self.file('00-manifest.sha256')
        if not manifest.is_file():
            self.notes.append('SHA-256 manifest is missing. Collection may be incomplete.')
            return 'missing'
        failed = False
        with manifest.open(encoding='utf-8-sig', errors='replace') as lines:
            for line in lines:
                match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](.+)', line.rstrip('\r\n'))
                if not match:
                    failed = True
                    self.notes.append('Malformed SHA-256 manifest entry')
                    continue
                relative = match[2]
                try:
                    path = self.file(local_path(relative))
                    if relative in self.checked_files or not path.is_file() or digest(path) != match[1].lower():
                        raise ValueError('Invalid or duplicate entry')
                except (OSError, ValueError):
                    self.bad_files.add(relative)
                    self.notes.append(f'Manifest check failed for {relative}')
                self.checked_files.add(relative)
        if not self.checked_files:
            self.notes.append('SHA-256 manifest contains no file entries')
            return 'failed'
        if failed or self.bad_files:
            return 'failed'
        return 'verified'

    def unlisted(self, relative):
        return self.integrity != 'missing' and relative not in self.checked_files

    def read_events(self, relative, channel):
        events = []
        issues = defaultdict(int)

        def warn(message):
            issues[message.split(':', 1)[0] if not message.startswith('EVTX record ') else 'EVTX decoding error'] += 1

        try:
            path = self.file(relative)
            exists = path.is_file()
            if relative in self.bad_files:
                warn('Manifest check failed')
            elif exists:
                if self.unlisted(relative):
                    warn('File is absent from the manifest')
                for rid, stamp, xml in records(path, on_issue=warn, xml_safe=True):
                    try:
                        event = event_details(rid, stamp, xml)
                    except (ET.ParseError, ValueError):
                        warn('Invalid event XML or fields')
                        continue
                    if event.channel.casefold() != channel.casefold():
                        warn('Record channel does not match file')
                        continue
                    events.append(event)
        except (OSError, ValueError):
            exists = True
            warn('Cannot read event log')
        expected = self.log_counts.get(channel)
        if expected is not None and len(events) != expected:
            warn(f'Collection summary lists {expected} records, read {len(events)}')
        dates = [event.timestamp for event in events if event.timestamp is not None]
        self.sources[channel] = {
            'path': relative, 'status': source_state(len(events), issues, exists),
            'records': len(events) if exists and (events or not issues) else None,
            'record_count_at_export': expected,
            'first_utc': timestamp(min(dates, default=None)), 'last_utc': timestamp(max(dates, default=None)),
            'records_without_time': len(events) - len(dates), 'issues': dict(issues),
        }
        return sorted(events, key=lambda event: event.record_id)
