"""Minimal EVTX reader: chunks -> records -> BinXML -> XML text."""
from __future__ import annotations

import struct, datetime, uuid
from dataclasses import dataclass
from xml.etree import ElementTree
from xml.sax.saxutils import escape


def ft(v):
    if not v:
        return None
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)
    except Exception:
        return None


def read_name(ch, off):
    num = struct.unpack_from('<H', ch, off + 6)[0]
    s = ch[off + 8:off + 8 + num * 2].decode('utf-16-le', 'ignore')
    return s, 8 + num * 2 + 2


def read_value(ch, off, vtype, size):
    b = ch[off:off + size]
    try:
        if vtype == 0x00:
            return ''
        if vtype == 0x01:
            return b.decode('utf-16-le', 'ignore').rstrip('\x00')
        if vtype == 0x02:
            return b.decode('latin1').rstrip('\x00')
        if vtype == 0x03:
            return str(struct.unpack_from('<b', b, 0)[0])
        if vtype == 0x04:
            return str(b[0])
        if vtype == 0x05:
            return str(struct.unpack_from('<h', b, 0)[0])
        if vtype == 0x06:
            return str(struct.unpack_from('<H', b, 0)[0])
        if vtype == 0x07:
            return str(struct.unpack_from('<i', b, 0)[0])
        if vtype == 0x08:
            return str(struct.unpack_from('<I', b, 0)[0])
        if vtype == 0x09:
            return str(struct.unpack_from('<q', b, 0)[0])
        if vtype == 0x0A:
            return str(struct.unpack_from('<Q', b, 0)[0])
        if vtype == 0x0B:
            return str(struct.unpack_from('<f', b, 0)[0])
        if vtype == 0x0C:
            return str(struct.unpack_from('<d', b, 0)[0])
        if vtype == 0x0D:
            return 'true' if struct.unpack_from('<I', b, 0)[0] else 'false'
        if vtype == 0x0E:
            return b.hex()
        if vtype == 0x0F:
            return str(uuid.UUID(bytes_le=b[:16]))
        if vtype == 0x10:
            return str(int.from_bytes(b, 'little'))
        if vtype == 0x11:
            return str(ft(struct.unpack_from('<Q', b, 0)[0]))
        if vtype == 0x13:  # SID
            rev, cnt = b[0], b[1]
            auth = int.from_bytes(b[2:8], 'big')
            subs = struct.unpack_from('<%dI' % cnt, b, 8)
            return 'S-%d-%d-' % (rev, auth) + '-'.join(str(x) for x in subs)
        if vtype == 0x14:
            return '0x%08x' % struct.unpack_from('<I', b, 0)[0]
        if vtype == 0x15:
            return '0x%016x' % struct.unpack_from('<Q', b, 0)[0]
    except Exception:
        return b.hex()
    return b.hex()


class Parser:
    def __init__(self, ch, xml_safe=False):
        self.ch = ch
        self.xml_safe = xml_safe

    def text(self, value):
        if not self.xml_safe:
            return value
        return escape(''.join(c for c in value if c in '\t\r\n' or 32 <= ord(c) <= 0xD7FF
                              or 0xE000 <= ord(c) <= 0xFFFD or ord(c) >= 0x10000), {'"': '&quot;'})

    def fragment(self, off, subs, out, depth=0):
        ch = self.ch
        while off < len(ch):
            tok = ch[off]
            t = tok & 0x0f
            if t == 0x00:
                off += 1
                return off
            elif t == 0x0f:
                off += 4
            elif t == 0x0c:
                off = self.template(off, out, depth)
                return off
            elif t == 0x01:
                off = self.element(off, subs, out, depth)
            elif t == 0x04:
                off += 1
                return off
            elif t == 0x02:
                off += 1
            elif t == 0x03:
                off += 1
                return off
            elif t == 0x05:
                off += 1
                vt = ch[off]
                off += 1
                if vt == 0x01:
                    n = struct.unpack_from('<H', ch, off)[0]
                    off += 2
                    out.append(self.text(ch[off:off + n * 2].decode('utf-16-le', 'ignore')))
                    off += n * 2
                else:
                    return off
            elif t in (0x0d, 0x0e):
                sid = struct.unpack_from('<H', ch, off + 1)[0]
                off += 4
                if sid < len(subs):
                    out.append(subs[sid])
            elif t == 0x06:
                off = self.attribute(off, subs, out, depth)
            else:
                return off
        return off

    def attribute(self, off, subs, out, depth):
        ch = self.ch
        off += 1
        noff = struct.unpack_from('<I', ch, off)[0]
        off += 4
        name, nsz = read_name(ch, noff)
        if noff == off:
            off += nsz
        out.append(' %s="' % name)
        off = self.fragment_value(off, subs, out, depth)
        out.append('"')
        return off

    def fragment_value(self, off, subs, out, depth):
        ch = self.ch
        tok = ch[off]
        t = tok & 0x0f
        if t == 0x05:
            off += 1
            vt = ch[off]
            off += 1
            if vt == 0x01:
                n = struct.unpack_from('<H', ch, off)[0]
                off += 2
                out.append(self.text(ch[off:off + n * 2].decode('utf-16-le', 'ignore')))
                off += n * 2
            return off
        if t in (0x0d, 0x0e):
            sid = struct.unpack_from('<H', ch, off + 1)[0]
            off += 4
            if sid < len(subs):
                out.append(subs[sid])
            return off
        return off

    def element(self, off, subs, out, depth):
        ch = self.ch
        tok = ch[off]
        has_attr = bool(tok & 0x40)
        off += 1
        off += 2  # dependency id
        off += 4  # data size
        noff = struct.unpack_from('<I', ch, off)[0]
        off += 4
        name, nsz = read_name(ch, noff)
        if noff == off:
            off += nsz
        out.append('<' + name)
        if has_attr:
            off += 4  # attribute list size
            while True:
                tk = ch[off] & 0x0f
                if tk != 0x06:
                    break
                off = self.attribute(off, subs, out, depth)
        tk = ch[off]
        if (tk & 0x0f) == 0x03:
            out.append('/>')
            return off + 1
        off += 1  # close start element
        out.append('>')
        off = self.fragment(off, subs, out, depth + 1)
        out.append('</%s>' % name)
        return off

    def template(self, off, out, depth):
        ch = self.ch
        off += 1
        off += 1  # version
        off += 4  # template id
        toff = struct.unpack_from('<I', ch, off)[0]
        off += 4
        if toff >= off - 4:
            dsz = struct.unpack_from('<I', ch, toff + 0x14)[0]
            off = toff + 0x18 + dsz
        cnt = struct.unpack_from('<I', ch, off)[0]
        off += 4
        descs = []
        for i in range(cnt):
            sz, vt = struct.unpack_from('<HB', ch, off)
            off += 4
            descs.append((sz, vt))
        subs = []
        for sz, vt in descs:
            if vt == 0x21:
                sub = []
                try:
                    self.fragment(off, [], sub, depth + 1)
                except Exception:
                    pass
                subs.append(''.join(sub))
            else:
                subs.append(self.text(read_value(ch, off, vt, sz)))
            off += sz
        self.fragment(toff + 0x18, subs, out, depth)
        return off


def records(path, *, on_issue=None, xml_safe=False):
    """Read EVTX one chunk at a time. Report structural problems when requested."""
    def warn(message):
        if on_issue is not None:
            on_issue(message)

    with open(path, 'rb') as stream:
        header = stream.read(4096)
        if len(header) != 4096 or header[:8] != b'ElfFile\x00':
            warn('Invalid or incomplete EVTX file header')
            return
        for number, chunk in enumerate(iter(lambda: stream.read(65536), b''), 1):
            if len(chunk) != 65536:
                warn(f'Incomplete EVTX chunk {number}')
            if chunk[:8] != b'ElfChnk\x00' or len(chunk) < 512:
                if any(chunk):
                    warn(f'Invalid EVTX chunk {number}')
                continue
            yield from chunk_records(chunk, number, warn, xml_safe)


def chunk_records(ch, number, warn, xml_safe):
    free = struct.unpack_from('<I', ch, 0x30)[0]
    if not 512 <= free <= 65536:
        warn(f'Invalid record boundary in EVTX chunk {number}')
        return
    ro = 0x200
    limit = min(free, len(ch))
    while ro < limit:
        if ro + 28 > limit or struct.unpack_from('<I', ch, ro)[0] != 0x2a2a:
            warn(f'Unreadable record in EVTX chunk {number}')
            break
        size = struct.unpack_from('<I', ch, ro + 4)[0]
        if size < 28 or ro + size > limit:
            warn(f'Invalid record size in EVTX chunk {number}')
            break
        rid = struct.unpack_from('<Q', ch, ro + 8)[0]
        ts = ft(struct.unpack_from('<Q', ch, ro + 16)[0])
        out = []
        try:
            Parser(ch, xml_safe).fragment(ro + 24, [], out)
        except Exception as e:
            warn(f'EVTX record {rid}: {type(e).__name__}')
            out.append('<PARSE_ERROR>%s</PARSE_ERROR>' % type(e).__name__)
        yield rid, ts, ''.join(out)
        ro += size


@dataclass
class Event:
    record_id: int
    timestamp: datetime.datetime | None
    channel: str
    provider: str
    event_id: int
    data: dict
    values: list


def event_details(record_id, timestamp, xml):
    """Extract system fields, named payload and positional data from one event."""
    root = ElementTree.fromstring(xml)
    for node in root.iter():
        node.tag = node.tag.rsplit('}', 1)[-1]
    system = root.find('System')
    if system is None or root.find('.//PARSE_ERROR') is not None:
        raise ValueError('Missing or incomplete event fields')
    provider = system.find('Provider')
    channel = system.findtext('Channel')
    provider_name = provider.get('Name') if provider is not None else None
    if not channel or not provider_name:
        raise ValueError('Missing channel or provider')
    data, values = {}, []
    for payload in (root.find('EventData'), root.find('UserData')):
        if payload is None:
            continue
        for field in payload.iter():
            if field is payload or len(field):
                continue
            value = field.text or ''
            name = field.get('Name') or (field.tag if field.tag != 'Data' else '')
            if name:
                data[name.casefold()] = value
            values.append(value)
    return Event(record_id, timestamp, channel, provider_name, int(system.findtext('EventID', '')), data, values)


if __name__ == '__main__':
    import sys, re
    if len(sys.argv) < 2:
        print('usage: python3 evtx_read.py <file.evtx> [XML search regex]')
        raise SystemExit(2)
    pat = re.compile(sys.argv[2]) if len(sys.argv) > 2 else None
    n = 0
    for rid, ts, xml in records(sys.argv[1]):
        if pat and not pat.search(xml):
            continue
        n += 1
        print('%s  %s' % (ts, xml))
    print('# records printed: %d' % n, file=sys.stderr)
