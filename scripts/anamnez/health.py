#!/usr/bin/env python3
"""Build an offline Windows health report from an Anamnez capture."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from html import escape
import json
from pathlib import Path
import re
import sys
import tempfile

script_dir = Path(__file__).resolve().parent
sys.path[:0] = [str(script_dir), str(script_dir.parent)]
from health_input import Capture, capture_folder, source_state, timestamp, utc
from evtx_read import Event
import wer_info


@dataclass(frozen=True)
class Evidence:
    kind: str
    source: str
    path: str
    time: datetime | None
    code: int | None = None
    params: tuple = ()
    subject: str = ''
    report_ids: tuple = ()
    boot: int | None = None
    event: Event | None = None

    def reference(self):
        ref = {'kind': self.kind, 'source': self.source, 'path': self.path, 'observed_utc': timestamp(self.time)}
        if self.event is not None:
            ref.update(channel=self.event.channel, provider=self.event.provider, event_id=self.event.event_id,
                       record_id=self.event.record_id)
        if self.report_ids:
            ref['report_ids'] = self.report_ids
        return ref


@dataclass
class Episode:
    primary: Evidence
    evidence: list = field(default_factory=list)

    def __post_init__(self):
        self.evidence.append(self.primary)

    @property
    def time(self):
        for source in ('wer_file', 'system_bugcheck', 'kernel_power', 'application_wer'):
            for item in self.evidence:
                if item.source == source and item.time is not None:
                    return item.time
        return self.primary.time


RULES = {
    'bugcheck': ('OS and power', 'critical', 'Windows stopped (bugcheck)',
                 'Check the stop code and available dumps. A code alone does not identify the failed part.'),
    'unexpected_shutdown': ('OS and power', 'warning', 'Unexpected shutdown or restart',
                            'Check what preceded the restart. This record alone does not identify the cause.'),
    'dump_failed': ('OS and power', 'warning', 'Crash dump write failed',
                    'Check the dump settings, page file and free disk space.'),
    'live_kernel': ('OS and power', 'warning', 'Live kernel event',
                    'Check the related driver and device history. Windows recorded a live kernel event.'),
    'app_crash': ('Applications', 'warning', 'Application stopped or hung',
                  'Check whether the same application and failure recur.'),
    'disk_bad_block': ('Storage', 'critical', 'Windows reported a bad disk block',
                       'Confirm the physical disk before checking SMART or replacing a drive.'),
    'disk_io': ('Storage', 'warning', 'Disk I/O error',
                'Confirm the device and check its connection and SMART data.'),
    'whea_fatal': ('Hardware', 'critical', 'Uncorrected hardware error reported by WHEA',
                   'Review the WHEA payload and test the affected component.'),
    'whea_corrected': ('Hardware', 'warning', 'Corrected hardware error reported by WHEA',
                       'Check the WHEA payload for repeated errors on the same device.'),
}

LOG_RULES = {
    ('disk', 7): 'disk_bad_block',
    ('disk', 51): 'disk_io',
    ('disk', 153): 'disk_io',
    ('microsoft-windows-whea-logger', 18): 'whea_fatal',
    ('microsoft-windows-whea-logger', 19): 'whea_corrected',
    ('microsoft-windows-whea-logger', 17): 'whea_corrected',
}
APP_REPORTS = {'appcrash', 'moappcrash', 'bex', 'bex64', 'apphangb1', 'apphangxprocb1', 'moapphang'}
SMART_STATUS = {'passed': 'Overall check passed', 'failed': 'Overall check failed',
                'unavailable': 'Overall status unavailable'}


def hex_code(value):
    code = wer_info.hexval(value)
    return code if code is not None and 0 < code <= 0xFFFFFFFF else None


def system_evidence(events, capture):
    out = []
    boot = previous_id = None
    prev_stamp = None
    for event in events:
        provider, number = event.provider.casefold(), event.event_id
        stamp, data = event.timestamp, event.data
        if previous_id is not None and event.record_id <= previous_id:
            capture.clock_notes.append('System record numbers are not unique')
            boot = None
        previous_id = event.record_id
        if stamp is not None:
            if (prev_stamp is not None and prev_stamp - stamp > timedelta(minutes=5)
                    or stamp.year < 2005
                    or capture.collected and stamp > capture.collected + timedelta(days=1)):
                capture.clock_notes.append('System event times include a backward jump or an implausible date')
            prev_stamp = stamp
        if provider == 'microsoft-windows-kernel-general':
            if number == 12:
                boot = event.record_id
            elif number == 1:
                old, new = utc(data.get('oldtime')), utc(data.get('newtime'))
                if old is not None and new is not None and abs(old - new) > timedelta(minutes=5):
                    capture.clock_notes.append('Windows recorded a large clock change')
        if provider == 'microsoft-windows-kernel-boot' and number == 238 and capture.collected is not None:
            efi = utc(data.get('efitime'))
            if efi is not None and abs(capture.collected - efi) > timedelta(days=365):
                capture.clock_notes.append('A recorded firmware clock differs from the capture date by over a year')

        args = {'path': 'evt/System.evtx', 'time': stamp, 'boot': boot, 'event': event}
        if provider == 'microsoft-windows-kernel-power' and number == 41:
            raw = data.get('bugcheckcode', '').strip()
            code = int(raw) if re.fullmatch(r'[0-9]{1,10}', raw) else hex_code(raw) if raw.startswith('0x') else None
            code = code if code and 0 < code <= 0xFFFFFFFF else None
            params = tuple(wer_info.hexval(data.get(f'bugcheckparameter{i}')) for i in range(1, 5))
            out.append(Evidence('bugcheck' if code else 'unexpected_shutdown', 'kernel_power',
                                code=code, params=params, **args))
        elif number == 1001 and provider in ('microsoft-windows-wer-systemerrorreporting', 'bugcheck', 'save dump'):
            code_text = data.get('param1') or next((v for v in event.values if v.strip().startswith('0x')), '')
            values = re.findall(r'0x[0-9a-f]+', code_text, re.I)
            report_id = wer_info.report_token(data.get('reportid') or data.get('param3') or '')
            args['report_ids'] = (report_id,) if report_id else ()
            if values and hex_code(values[0]):
                out.append(Evidence('bugcheck', 'system_bugcheck', code=hex_code(values[0]),
                                    params=tuple(wer_info.hexval(value) for value in values[1:5]), **args))
            else:
                capture.notes.append('A System bugcheck record has no readable stop code')
                out.append(Evidence('bugcheck', 'system_bugcheck', **args))
        elif number == 161 and provider == 'volmgr':
            out.append(Evidence('dump_failed', 'dump_write_error', **args))
        elif (kind := LOG_RULES.get((provider, number))) is not None:
            subject = ''
            if kind.startswith('disk_'):
                devices = [device for value in event.values
                           for device in re.findall(r'\\Device\\Harddisk\d+(?:\\(?:DR|DP)\d+)?', value, re.I)]
                subject = devices[0] if devices else 'Device unknown'
            out.append(Evidence(kind, 'system_event', subject=subject, **args))
    return out


def wer_evidence(rep, path):
    kind = rep.etype.casefold()
    args = {'path': path, 'source': 'wer_file' if rep.src == 'wer' else 'application_wer',
            'time': None if rep.t == wer_info.MIN else rep.t, 'report_ids': rep.report_ids, 'event': rep.event}
    if kind in ('bluescreen', 'livekernelevent'):
        params = tuple(wer_info.hexval(value) for value in rep.sigs[1:5])
        return Evidence('bugcheck' if kind == 'bluescreen' else 'live_kernel',
                        code=wer_info.kernel_code(rep), params=params, **args)
    if kind in APP_REPORTS:
        return Evidence('app_crash', subject=rep.s(0, 'Application unknown') or 'Application unknown', **args)
    return None


def read_wer(capture, application):
    out = []
    issues = Counter()
    try:
        wer = capture.file('wer')
    except ValueError:
        capture.sources['WER files'] = {'path': 'wer/', 'status': 'unreadable', 'records': None,
                                        'issues': {'Links are not supported inside a capture': 1}}
        wer = None
    count = 0
    if wer is not None and wer.is_dir():
        files = sorted(path for path in wer.iterdir() if path.suffix.lower() == '.wer')
        for path in files:
            relative = path.relative_to(capture.root).as_posix()
            try:
                if relative in capture.bad_files:
                    issues['Manifest check failed'] += 1
                    continue
                if capture.unlisted(relative):
                    issues['File is absent from the manifest'] += 1
                rep = wer_info.from_wer(capture.file(relative))
                if rep.etype == '?':
                    issues['WER type missing'] += 1
                    continue
            except (OSError, ValueError):
                issues['Unreadable WER file'] += 1
                continue
            count += 1
            evidence = wer_evidence(rep, relative)
            if evidence is not None:
                out.append(evidence)
        if len(files) >= 500:
            issues['Collector WER limit reached'] += 1
    exists = wer is not None and wer.is_dir()
    status = source_state(count, issues, exists)
    setting = capture.metadata.get('wer')
    if count == 0 and not issues and setting and setting.startswith('OFF'):
        status = 'disabled'
    if wer is not None:
        capture.sources['WER files'] = {'path': 'wer/', 'status': status,
                                        'records': count if exists and (count or not issues) else None,
                                        'issues': dict(issues), 'setting': setting}
    for event in application:
        rep = wer_info.from_event(event)
        if rep is not None:
            evidence = wer_evidence(rep, 'evt/Application.evtx')
            if evidence is not None:
                out.append(evidence)
        elif event.event_id == 1001 and event.provider.casefold() == 'windows error reporting':
            source = capture.sources['Application']
            source['status'] = 'partial'
            source['issues']['Unreadable WER payload'] = source['issues'].get('Unreadable WER payload', 0) + 1
    return out


def wer_episodes(evidence):
    by_id = defaultdict(set)
    episodes = []
    for item in evidence:
        keys = [(item.kind, token) for token in item.report_ids]
        matches = {index for key in keys for index in by_id[key]
                   if compatible_codes(item, episodes[index].primary)}
        if len(matches) == 1:
            index = matches.pop()
            episode = episodes[index]
            episode.evidence.append(item)
            if episode.primary.code is None and item.code is not None:
                episode.primary = item
        else:
            index = len(episodes)
            episodes.append(Episode(item))
        for key in keys:
            by_id[key].add(index)
    return episodes


def time_near(left, right, minutes):
    return left is not None and right is not None and abs(left - right) <= timedelta(minutes=minutes)


def param_match(left, right):
    comparable = [(a, b) for a, b in zip(left, right) if a is not None and b is not None]
    return all(a == b for a, b in comparable), any(a == b != 0 for a, b in comparable)


def same_boot(left, right):
    return left.boot is not None and left.boot == right.boot


def compatible_codes(left, right):
    return left.code is None or right.code is None or left.code == right.code


def same_system_crash(left, right, good_clock):
    a, b = left.primary, right.primary
    compatible, corroborated = param_match(a.params, b.params)
    if not compatible or not compatible_codes(a, b):
        return False
    if same_boot(a, b):
        return True
    return (good_clock and (a.boot is None or b.boot is None) and a.code is not None and a.code == b.code
            and corroborated and time_near(a.time, b.time, 5))


def same_wer_crash(system, wer, good_clock):
    if not compatible_codes(system.primary, wer.primary):
        return False
    for a in system.evidence:
        for b in wer.evidence:
            if set(a.report_ids).intersection(b.report_ids):
                return True
            compatible, corroborated = param_match(a.params, b.params)
            if (good_clock and a.code is not None and a.code == b.code and compatible
                    and corroborated and time_near(a.time, b.time, 10)):
                return True
    return False


def merge_unique(left, right, matches):
    """Merge only pairs with a unique partner on both sides."""
    candidates = defaultdict(list)
    reverse = Counter()
    for i, first in enumerate(left):
        for j, second in enumerate(right):
            if matches(first, second):
                candidates[i].append(j)
                reverse[j] += 1
    merged = set()
    ambiguous = False
    for i, indices in candidates.items():
        if len(indices) == 1 and reverse[indices[0]] == 1:
            j = indices[0]
            if left[i].primary.code is None and right[j].primary.code is not None and left[i].primary.kind == 'bugcheck':
                left[i].primary = right[j].primary
            left[i].evidence.extend(right[j].evidence)
            merged.add(j)
        else:
            ambiguous = True
    return [episode for j, episode in enumerate(right) if j not in merged], ambiguous


def correlate(system, wer, good_clock):
    explicit, power, other, failures = [], [], [], []
    for item in system:
        bucket = {'system_bugcheck': explicit, 'kernel_power': power, 'dump_write_error': failures}.get(item.source, other)
        bucket.append(Episode(item))
    left_power, ambiguous = merge_unique(explicit, power, lambda a, b: same_system_crash(a, b, good_clock))
    kernel = explicit + [episode for episode in left_power if episode.primary.kind == 'bugcheck']
    unexpected = [episode for episode in left_power if episode.primary.kind == 'unexpected_shutdown']
    wer_kernel = [episode for episode in wer if episode.primary.kind == 'bugcheck']
    wer_other = [episode for episode in wer if episode.primary.kind != 'bugcheck']
    unmatched_wer, uncertain_wer = merge_unique(kernel, wer_kernel, lambda a, b: same_wer_crash(a, b, good_clock))
    unmatched_dumps, uncertain_dumps = merge_unique(
        kernel + unexpected, failures,
        lambda a, b: any(same_boot(item, b.primary) for item in a.evidence)
        and (not good_clock or time_near(a.time, b.time, 10) or a.time is None or b.time is None))
    return kernel + unexpected + unmatched_wer + unmatched_dumps + other + wer_other, (
        ambiguous or uncertain_wer or uncertain_dumps)


def findings(episodes, clock_ok, collected):
    groups = defaultdict(list)
    for episode in episodes:
        item = episode.primary
        groups[(item.kind, item.code, item.subject)].append(episode)
    out = []
    for (kind, code, subject), grouped in groups.items():
        section, priority, title, follow_up = RULES[kind]
        dates = [episode.time for episode in grouped if episode.time is not None]
        missing_time = len(dates) != len(grouped)
        evidence = [item for episode in grouped for item in episode.evidence]
        events = sum(item.event is not None for item in evidence)
        files = len(evidence) - events
        # These are observed counts inside the available history, not estimated rates.
        windows = {str(days): sum(collected - timedelta(days=days) <= stamp <= collected for stamp in dates)
                   if clock_ok and collected is not None and not missing_time else None for days in (7, 30)}
        out.append({
            'kind': kind, 'section': section, 'priority': priority, 'title': title, 'subject': subject or None,
            'code': f'0x{code:X}' if code is not None else None, 'event_records': events, 'report_files': files,
            'related_dump_errors': sum(item.kind == 'dump_failed' for item in evidence) if kind != 'dump_failed' else 0,
            'episodes': len(grouped), 'observed_first_utc': timestamp(min(dates, default=None)) if clock_ok else None,
            'observed_last_utc': timestamp(max(dates, default=None)) if clock_ok else None, 'windows_days': windows,
            'evidence_confidence': 'recorded', 'episode_basis': 'observed and conservatively matched',
            'next_check': follow_up,
            'details': [{'observed_utc': timestamp(episode.time), 'time_trusted': clock_ok and episode.time is not None,
                         'evidence': [item.reference() for item in episode.evidence]} for episode in grouped],
        })
    return sorted(out, key=lambda item: (item['priority'] != 'critical', -item['episodes'], item['kind'],
                                         item['code'] or '', item['subject'] or ''))


def smart_results(capture, paths):
    out = []
    for path in sorted(paths):
        relative = path.relative_to(capture.root).as_posix()
        text = capture.text(relative)
        model = re.search(r'^(?:Device Model|Model Number|Product):[ \t]*(\S[^\r\n]*)', text, re.M)
        result = re.search(r'^SMART (?:overall-health self-assessment test result|Health Status):'
                           r'[ \t]*(\S[^\r\n]*)', text, re.M | re.I)
        value = result[1].strip() if result else None
        status = 'unavailable'
        if value:
            normalized = value.upper().rstrip('!')
            if normalized in ('PASSED', 'OK'):
                status = 'passed'
            elif normalized == 'FAILED' or normalized.startswith(
                    ('HARDWARE IMPENDING FAILURE', 'FAILURE PREDICTION THRESHOLD EXCEEDED')):
                status = 'failed'
        out.append({'path': relative, 'model': model[1].strip() if model else None,
                    'status': status, 'reported_result': value})
    return out


def build_report(root):
    capture = Capture(root)
    system = system_evidence(capture.read_events('evt/System.evtx', 'System'), capture)
    app = capture.read_events('evt/Application.evtx', 'Application')
    wer = read_wer(capture, app)
    if capture.collected and any(item.time and item.time > capture.collected + timedelta(days=1) for item in wer):
        capture.clock_notes.append('Some WER times are later than the capture date')
    clock_ok = not capture.clock_notes
    episodes, ambiguous = correlate(system, wer_episodes(wer), clock_ok)
    if ambiguous:
        capture.notes.append('Some records had more than one possible match and were kept separate')
    capture.notes.append('Unmatched records may describe the same incident. Counts cover retained and readable records only.')
    if any(source['status'] in ('missing', 'partial', 'unreadable', 'disabled')
           for source in capture.sources.values()):
        capture.notes.append('Some diagnostic sources are unavailable or incomplete.')
    if capture.collected is None:
        capture.notes.append('Capture time or UTC offset is missing. Recent windows are unavailable.')
    smart = []
    for label, folder, pattern in (('Dump files', 'dumps', r'.+\.dmp'), ('SMART files', 'info', r'smart-.+\.txt')):
        try:
            paths = [path for path in capture.file(folder).rglob('*')
                     if re.fullmatch(pattern, path.name, re.I) and path.name.lower() != 'smart-scan.txt'
                     and path.is_file() and not path.is_symlink()]
            status = 'present_not_analyzed' if paths else 'missing'
        except (OSError, ValueError):
            paths, status = [], 'unreadable'
        if label == 'SMART files' and paths:
            smart = smart_results(capture, paths)
            status = 'readable' if any(item['reported_result'] for item in smart) else 'status_unavailable'
        capture.sources[label] = {'path': folder + '/', 'status': status, 'records': len(paths) if paths else None,
                                  'issues': {}}
    skipped_dumps = sum(line.startswith('TOO BIG') for line in capture.text('info/dumps-list.txt').splitlines())
    if skipped_dumps:
        capture.sources['Dump files']['issues']['Collector skipped large dumps'] = skipped_dumps
    result = findings(episodes, clock_ok, capture.collected)
    sections = {}
    for section, sources in {
        'OS and power': ('System', 'Application', 'WER files'),
        'Applications': ('Application', 'WER files'),
        'Storage': ('System',),
        'Hardware': ('System',),
    }.items():
        matching = [item for item in result if item['section'] == section]
        statuses = [capture.sources[source]['status'] for source in sources]
        status = matching[0]['priority'] if matching else (
            'no_signals_found' if 'readable' in statuses else 'no_data')
        if section == 'Applications' and not matching and capture.sources['WER files']['status'] == 'disabled':
            status = 'no_data'
        sections[section] = status
    for section in ('Drivers and devices', 'Network', 'Boot and services', 'Security'):
        sections[section] = 'not_analyzed'
    if any(item['status'] == 'failed' for item in smart):
        sections['Storage'] = 'critical'
    return {
        'schema_version': 1, 'integrity': capture.integrity, 'machine': capture.metadata,
        'clock': {'status': 'suspect' if capture.clock_notes else 'no_issue_found',
                  'notes': list(dict.fromkeys(capture.clock_notes))},
        'sources': capture.sources, 'sections': sections, 'smart': smart, 'findings': result,
        'notes': list(dict.fromkeys(capture.notes)),
    }


REPORT_TITLE = 'Anamnez - Windows health report'
STATUS_STYLES = {'critical': 'critical', 'warning': 'warning', 'no_signals_found': 'clear'}
REFERENCE_NAMES = {
    'kernel_power': 'Startup after an unclean shutdown',
    'system_bugcheck': 'Windows stop code',
    'application_wer': 'Windows Error Reporting event',
    'wer_file': 'Windows Error Reporting file',
    'dump_write_error': 'Crash dump write failure',
}
HTML_STYLE = """
html { color-scheme: dark; background: #10141c; color: #e6edf7; }
body { max-width: 66rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; font: 15px/1.48 "Segoe UI", system-ui, sans-serif; }
h1 { font-size: 1.6rem; margin: 0 0 1rem; }
h2 { font-size: 1.15rem; margin: 1.55rem 0 .6rem; }
pre { color: #c0cbd9; font: 13px/1.5 Consolas, monospace; white-space: pre-wrap; word-wrap: break-word; margin: 0; }
p { margin: .3rem 0; }
.summary { padding: .75rem 1rem; background: #171d26; border: 1px solid #303c4d; border-radius: .45rem; }
.clock { color: #ffd08c; }
.subsystems { margin: 0; }
.subsystems div { margin: .18rem 0; padding: .35rem .55rem; }
.subsystems dt { display: inline-block; min-width: 52%; }
.subsystems dd { display: inline-block; margin: 0; font-weight: 600; }
.stripe { border-left: 3px solid; }
.critical { border-color: #d56978; background: #2a1c27; }
.warning { border-color: #d79b54; background: #2b241f; }
.clear { border-color: #619d84; background: #172826; }
.muted { border-color: #394555; background: #171d26; }
.critical .severity { color: #ff9ca6; }
.warning .severity { color: #ffd08c; }
.clear .severity { color: #89d4b2; }
.muted .severity { color: #afbac9; }
.finding { padding: .65rem .8rem; margin: .55rem 0; }
.finding summary { cursor: pointer; display: flex; align-items: baseline; gap: .55rem; padding-right: .5rem; list-style: none; }
.finding summary::-webkit-details-marker { display: none; }
.finding summary::before { content: "▸"; color: #b9c6d6; flex-shrink: 0; }
.finding[open] summary::before { content: "▾"; }
.finding-title { flex: 1; min-width: 0; font-weight: 600; overflow-wrap: anywhere; }
.finding-count { flex-shrink: 0; margin-left: auto; text-align: right; white-space: nowrap; color: #b9c6d6; font-size: .88rem; }
.finding-body { margin-top: .65rem; }
.muted-text, .reference { color: #b9c6d6; }
.episode-heading { font-weight: 600; margin-top: .65rem; }
.records { list-style: none; padding: 0; margin: 0; }
.records li { padding: .25rem 0; border-top: 1px solid #394555; overflow-wrap: anywhere; }
.record-time { display: inline-block; min-width: 21ch; font-variant-numeric: tabular-nums; }
.reference { display: block; font-size: .87rem; margin-left: 21ch; }
@media (max-width: 33rem) { .reference { margin-left: 0; } }
"""


def summary_lines(report):
    machine = report['machine']
    for key in ('host', 'os', 'machine', 'cpu', 'ram', 'disk', 'time_zone', 'collected_utc', 'dump_mode', 'wer'):
        value = machine.get(key)
        if value is not None or key in ('host', 'os', 'collected_utc'):
            label = {'os': 'OS', 'cpu': 'CPU', 'ram': 'RAM', 'wer': 'WER', 'collected_utc': 'Captured (UTC)'}.get(
                key, key.replace('_', ' ').capitalize())
            yield f'{label}: ' + (', '.join(value) if isinstance(value, list) else value or 'unknown')
    yield 'Integrity: ' + report['integrity']
    yield 'Clock: ' + report['clock']['status'].replace('_', ' ')
    failed = machine['failed_steps']
    yield 'Failed collection steps: ' + (str(failed) if failed is not None else 'unknown')


def display_time(stamp):
    if not stamp:
        return 'Time unavailable'
    time = stamp.replace('T', ' ', 1)
    return time[:-1] + ' UTC' if time.endswith('Z') else time


def time_note(report):
    if report['clock']['status'] == 'suspect':
        return 'The clock changed or looks wrong. Times below are recorded values and may be incorrect.'
    return 'Times below are as recorded, in UTC.'


def finding_title(item):
    return ' '.join(filter(None, (item['title'], item['code'], item['subject'])))


def finding_count(item):
    episodes = item['episodes']
    rows = item['event_records'] + item['report_files']
    return f'{episodes} episode{"s" if episodes != 1 else ""} · {rows} row{"s" if rows != 1 else ""}'


def smart_lines(report):
    for item in report.get('smart', ()):
        status = item['status']
        title = item['model'] or Path(item['path']).stem
        result = SMART_STATUS[status]
        if item['reported_result']:
            result += f' ({item["reported_result"]})'
        yield status, f'{title}: {result}', item['path']


def finding_summary(item):
    if item['kind'] == 'bugcheck':
        if item['code'] == '0x116':
            yield 'Windows failed to recover the display driver after a timeout and stopped (BSOD).'
        yield 'Each episode is one Windows stop. Several records can refer to the same stop.'
    elif item['kind'] == 'unexpected_shutdown':
        yield 'Windows logged these events at the next startup, after an unclean shutdown.'
    yield f'Episodes: {item["episodes"]} | Event records: {item["event_records"]} | WER files: {item["report_files"]}'
    if item['related_dump_errors']:
        yield f'Related dump write errors: {item["related_dump_errors"]}'
    first, last = item['observed_first_utc'], item['observed_last_utc']
    if first and last:
        yield f'First recorded: {display_time(first)} | Last recorded: {display_time(last)}'
    windows = {days: count for days, count in item['windows_days'].items() if count is not None}
    if windows:
        yield 'Recent episodes: ' + ', '.join(f'{days}d: {count}' for days, count in windows.items())
    else:
        yield 'Recent episode counts unavailable.'
    yield item['next_check']


def episode_heading(number, episode):
    return f'Episode {number} | Recorded: {display_time(episode["observed_utc"])}'


def episode_references(episode):
    # Keep related System records in their log order, even when clocks disagree.
    return sorted(episode['evidence'], key=lambda ref: (
        ref.get('channel') != 'System', ref.get('record_id', 0) if ref.get('channel') == 'System' else 0))


def reference_location(ref):
    if 'record_id' in ref:
        return f'{ref["channel"]} / {ref["provider"]} {ref["event_id"]} / record {ref["record_id"]}'
    return ref['path']


def source_lines(report):
    for name, source in report['sources'].items():
        count = source['records']
        unit = 'files' if name.endswith('files') else 'records'
        yield f'  {name}: {source["status"].replace("_", " ")}' + (f' ({count} {unit})' if count is not None else '')
        if source.get('first_utc') or source.get('last_utc'):
            yield f'    Recorded range: {display_time(source["first_utc"])} to {display_time(source["last_utc"])}'
        if source.get('records_without_time'):
            yield f'    Records without time: {source["records_without_time"]}'
        for issue, qty in source['issues'].items():
            yield f'    {issue} ({qty})'


def report_lines(report):
    yield REPORT_TITLE
    yield from summary_lines(report)
    yield '\nSubsystems (rules evaluated)'
    for section, status in report['sections'].items():
        yield f'  {section}: {status.replace("_", " ")}'
    yield '\nSMART'
    rows = list(smart_lines(report))
    if not rows:
        yield '  No per-device SMART result captured.'
    for _, label, path in rows:
        yield f'  {label} | {path}'
    yield '\nFindings'
    if not report['findings']:
        yield '  No matching signals in the readable sources.'
    else:
        yield time_note(report)
    for item in report['findings']:
        yield f'  [{item["priority"].upper()}] {finding_title(item)}'
        for line in finding_summary(item):
            yield '    ' + line
        for index, episode in enumerate(item['details'][:3], 1):
            refs = episode_references(episode)
            if len(refs) > 1:
                yield '    ' + episode_heading(index, episode)
            for ref in refs:
                name = REFERENCE_NAMES.get(ref['source'], 'Event record')
                yield f'      {display_time(ref["observed_utc"])} | {name} | {reference_location(ref)}'
        if len(item['details']) > 3:
            yield f'    {len(item["details"]) - 3} more episodes in health.html and health.json'
    yield '\nSources'
    yield from source_lines(report)
    yield '\nNotes'
    notes = report['clock']['notes'] + report['notes'] + report['machine']['collection_failures']
    yield from ('  ' + note for note in notes)


def report_html(report):
    parts = ['<!doctype html>', '<html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             f'<title>{REPORT_TITLE}</title><style>{HTML_STYLE}</style></head><body>',
             f'<h1>{REPORT_TITLE}</h1><section class="summary"><pre>']
    for line in summary_lines(report):
        if line == 'Clock: suspect':
            parts.append(f'<span class="clock">{escape(line)}</span>')
        else:
            parts.append(escape(line))
    parts.append('</pre></section><section><h2>Subsystems (rules evaluated)</h2><dl class="subsystems">')
    for section, status in report['sections'].items():
        style = STATUS_STYLES.get(status, 'muted')
        parts.append(f'<div class="stripe {style}"><dt>{escape(section)}</dt> '
                     f'<dd class="severity">{escape(status.replace("_", " "))}</dd></div>')
    parts.append('</dl></section><section><h2>SMART</h2>')
    smart = list(smart_lines(report))
    if not smart:
        parts.append('<p>No per-device SMART result captured.</p>')
    for status, label, path in smart:
        style = {'passed': 'clear', 'failed': 'critical'}.get(status, 'muted')
        parts.append(f'<div class="finding stripe {style}"><span class="severity">{escape(label)}</span> '
                     f'<small>{escape(path)}</small></div>')
    parts.append('</section><section><h2>Findings</h2>')
    if not report['findings']:
        parts.append('<p>No matching signals in the readable sources.</p>')
    else:
        parts.append(f'<p class="muted-text">{escape(time_note(report))}</p>')
    for item in report['findings']:
        priority = item['priority']
        style = STATUS_STYLES[priority]
        opened = ' open' if priority == 'critical' else ''
        parts.append(f'<details class="finding stripe {style}"{opened}><summary>'
                     f'<span class="finding-title"><span class="severity">[{escape(priority.upper())}]</span> '
                     f'{escape(finding_title(item))}</span> '
                     f'<span class="finding-count">{escape(finding_count(item))}</span></summary>'
                     '<div class="finding-body">')
        parts.extend(f'<p>{escape(line)}</p>' for line in finding_summary(item))
        for index, episode in enumerate(item['details'], 1):
            refs = episode_references(episode)
            if len(refs) > 1:
                parts.append(f'<p class="episode-heading">{escape(episode_heading(index, episode))}</p>')
            parts.append('<ul class="records">')
            for ref in refs:
                name = REFERENCE_NAMES.get(ref['source'], 'Event record')
                parts.append(f'<li><span class="record-time">{escape(display_time(ref["observed_utc"]))}</span> '
                             f'{escape(name)}<span class="reference">{escape(reference_location(ref))}</span></li>')
            parts.append('</ul>')
        parts.append('</div></details>')
    notes = report['clock']['notes'] + report['notes'] + report['machine']['collection_failures']
    parts += ['</section><section><h2>Sources</h2><pre>', escape('\n'.join(source_lines(report))),
              '</pre></section><section><h2>Notes</h2><pre>', escape('\n'.join(notes)),
              '</pre></section></body></html>']
    return '\n'.join(parts) + '\n'


def write_reports(report, destination):
    if destination.exists() or destination.is_symlink():
        raise ValueError('Output folder already exists. Choose a new folder.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    text = '\n'.join(report_lines(report)) + '\n'
    html = report_html(report)
    with tempfile.TemporaryDirectory(prefix='.anamnez-', dir=destination.parent) as temp:
        staging = Path(temp) / 'report'
        staging.mkdir()
        contents = {'txt': text, 'html': html, 'json': json.dumps(report, ensure_ascii=False, indent=2) + '\n'}
        for extension, content in contents.items():
            (staging / f'health.{extension}').write_text(content, encoding='utf-8')
        staging.rename(destination)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path, help='Unpacked capture folder or collector .7z archive')
    parser.add_argument('-o', '--output', type=Path, help='New folder for reports (default: in the working directory)')
    args = parser.parse_args(argv)
    capture_path = args.capture.resolve()
    name = capture_path.stem if capture_path.is_file() else capture_path.name
    destination = (args.output or Path(name + '-health')).absolute()
    try:
        with capture_folder(args.capture) as root:
            root = root.resolve()
            output = destination.resolve()
            if output == root or root in output.parents:
                raise ValueError('Choose an output folder outside the capture')
            report = build_report(root)
        write_reports(report, destination)
    except (OSError, ValueError) as error:
        print(f'Anamnez: {error}', file=sys.stderr)
        return 2
    print(f'Reports: {destination}')
    if report['integrity'] != 'verified':
        print('Capture integrity is incomplete. See the report for details.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
