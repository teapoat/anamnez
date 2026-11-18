"""Summarize Windows Error Reporting (WER) data in an Anamnez capture.

    python3 scripts/anamnez/wer_info.py <capture directory> [...]

Group reports from wer/ and Application event 1001 by report ID where available.
Distinguish live kernel reports from blue screens and show recorded times in UTC.
"""
import datetime
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
try:
    from evtx_read import event_details, records  # noqa: E402
except ImportError:                # wer_info still works on wer/ alone
    records = None

# Some live dump codes carry the 0x10000000 flag.
CODES = {
    0x0A: 'IRQL_NOT_LESS_OR_EQUAL', 0x1A: 'MEMORY_MANAGEMENT',
    0x1E: 'KMODE_EXCEPTION_NOT_HANDLED', 0x3B: 'SYSTEM_SERVICE_EXCEPTION',
    0x50: 'PAGE_FAULT_IN_NONPAGED_AREA', 0x7E: 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED',
    0x9F: 'DRIVER_POWER_STATE_FAILURE', 0xD1: 'DRIVER_IRQL_NOT_LESS_OR_EQUAL',
    0xEF: 'CRITICAL_PROCESS_DIED', 0x116: 'VIDEO_TDR_FAILURE',
    0x117: 'VIDEO_TDR_TIMEOUT_DETECTED (display driver timeout)',
    0x124: 'WHEA_UNCORRECTABLE_ERROR', 0x133: 'DPC_WATCHDOG_VIOLATION',
    0x139: 'KERNEL_SECURITY_CHECK_FAILURE',
    0x141: 'VIDEO_ENGINE_TIMEOUT_DETECTED (graphics engine timeout)',
    0x144: 'BUGCODE_USB3_DRIVER (USB 3 controller or device failure)',
    0x15E: 'BUGCODE_NDIS_DRIVER_LIVE_DUMP (network driver)',
    0x15F: 'CONNECTED_STANDBY_WATCHDOG_TIMEOUT_LIVEDUMP (Modern Standby transition timeout)',
    0x193: 'VIDEO_DXGKRNL_LIVEDUMP (graphics kernel)',
}
# 0x15E / 0x7C: Parameter 1 and, for the watchdog, Parameter 2 (learn.microsoft.com,
# bug-check-0x15e-bugcode-ndis-driver-live-dump).
NDIS_P1 = {0x01: 'MINIPORT_FATAL_ERROR (the driver requested a reset)',
           0x25: 'WATCHDOG (a driver operation timed out)',
           0x30: 'STUCK_NBL (the driver did not return a network buffer)'}
NDIS_WD = {0x01: 'PROTOCOL_PAUSE', 0x02: 'PROTOCOL_NETPNPEVENT', 0x03: 'PROTOCOL_STATUS_INDICATION',
           0x04: 'PROTOCOL_UNBIND', 0x11: 'FILTER_PAUSE', 0x12: 'FILTER_NETPNPEVENT',
           0x13: 'FILTER_STATUS_INDICATION', 0x14: 'FILTER_DETACH',
           0x21: 'MINIPORT_PAUSE (pause the adapter)', 0x22: 'MINIPORT_HALT (stop the adapter)',
           0x23: 'MINIPORT_OID (adapter OID request timed out, P4 is the OID)',
           0x24: 'FILTER_OID', 0x25: 'MINIPORT_IDLE (enter idle)',
           0x26: 'CANCEL_IDLE (leave idle)'}

KERNEL_TYPES = ('LiveKernelEvent', 'BlueScreen')
FAULT_MODULE = r'^(fault module name|имя модуля с ошибкой)'  # cyrillic-ok: Localized WER field.
EXCEPTION_CODE = r'^(exception code|код исключения)'  # cyrillic-ok: Localized WER field.
MIN = datetime.datetime.min


class Rep:
    """One WER report: type, signature values in order, files it mentions."""
    def __init__(self, src, t, etype, sigs, rid, files, names=None, event=None, aliases=()):
        self.src, self.t, self.etype, self.sigs, self.rid, self.files = src, t or MIN, etype, sigs, rid, files
        self.names = names or []
        self.event = event
        self.report_ids = tuple(dict.fromkeys(token for token in (rid, *aliases) if token))

    def s(self, i, default=''):
        return self.sigs[i] if i < len(self.sigs) else default

    def named(self, pattern, pos, default=''):
        """By localized name when known (.wer), else by position (journal copy)."""
        rx = re.compile(pattern, re.I)
        for n, v in zip(self.names, self.sigs):
            if rx.search(n):
                return v
        return self.s(pos, default)


def filetime(v):
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(v) // 10)
    except (TypeError, ValueError, OverflowError):
        return None


UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'


def folder_id(name):
    """Report folder (= .wer file name) ends with a GUID that survives Queue -> Archive."""
    m = re.search('(' + UUID + r')(?:\.wer)?$', name, re.I)
    return m.group(1).lower() if m else ''


def report_token(value):
    value = value.strip().strip('{}').casefold()
    return value if re.fullmatch(UUID + r'|[0-9]{6}-[0-9]{1,8}-[0-9]{2}', value) else ''


def store_token(path):
    name = re.split(r'[\\/]', path.rstrip('\\/'))[-1].casefold()
    if name.endswith('.wer'):
        name = name[:-4]
    return 'folder:' + name if re.fullmatch(r'[a-z0-9][a-z0-9_.-]+', name) and '_' in name else ''


def from_wer(path):
    with open(path, 'rb') as source:
        raw = source.read()
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        text = raw.decode('utf-16', 'replace')
    elif 'EventType='.encode('utf-16-le') in raw:
        text = raw.decode('utf-16-le', 'replace')
    else:
        text = raw.decode('utf-8-sig', 'replace')
    kv = {}
    for line in text.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            kv[k.strip()] = v.strip()
    sigs, names = [], []
    for i in range(32):
        if 'Sig[%d].Value' % i not in kv:
            break
        sigs.append(kv['Sig[%d].Value' % i])
        names.append(kv.get('Sig[%d].Name' % i, ''))
    files = [v for k, v in kv.items() if k.startswith('File[') and k.endswith('.Original.Path')]
    name = os.path.basename(path)
    report_id = report_token(kv.get('ReportIdentifier', '')) or folder_id(name)
    return Rep('wer', filetime(kv.get('EventTime')), kv.get('EventType', '?'), sigs, report_id, files, names,
               aliases=(report_token(kv.get('IntegratorReportIdentifier', '')), store_token(name)))


def from_event(event):
    """Read named WER fields or the packed UTF-16 fields found in older exports."""
    if (event.channel.casefold() != 'application' or event.event_id != 1001
            or event.provider.casefold() not in ('windows error reporting', 'microsoft-windows-wer-systemerrorreporting')):
        return None
    data = event.data
    kind = data.get('eventname') or data.get('eventtype')
    if kind:
        sigs = [data.get(f'p{i}', '') for i in range(1, 11)]
        while sigs and not sigs[-1]:
            sigs.pop()
        folder = data.get('storepath', '')
        report_id = report_token(data.get('reportid') or data.get('reportidentifier') or '')
        files = data.get('attachedfiles', '').splitlines()
        return Rep('log', event.timestamp, kind, sigs, report_id or folder_id(folder), files, event=event,
                   aliases=(store_token(folder),))

    if len(event.values) >= 15 and event.values[2] and not event.values[2].isdigit():
        fields = event.values
    else:
        fields = []
        for blob in event.values:
            if not re.fullmatch(r'[0-9a-fA-F]{40,}', blob):
                continue
            try:
                candidate = bytes.fromhex(blob).decode('utf-16-le').split('\0')
            except ValueError:
                continue
            if len(candidate) >= 6 and candidate[2]:
                fields = candidate
                break
    if not fields:
        return None
    sigs = []
    for value in fields[5:15]:
        if value.startswith(('\r\n', '\\\\?\\')):
            break
        sigs.append(value)
    while sigs and not sigs[-1]:
        sigs.pop()
    files = [line.strip() for value in fields for line in value.splitlines() if line.strip().startswith('\\\\?\\')]
    folder = fields[16].strip() if len(fields) > 16 else ''
    if not re.search(r'\\WER\\Report(Queue|Archive)\\', folder, re.I):
        folder = next((x for x in files if re.search(r'\\WER\\Report(Queue|Archive)\\', x, re.I)), '')
    rid = report_token(fields[19]) if len(fields) > 19 else ''
    return Rep('log', event.timestamp, fields[2], sigs, rid or folder_id(folder), files, event=event,
               aliases=(store_token(folder),))


def from_journal(path):
    out = []
    if records is None or not os.path.isfile(path):
        return out
    for rid, ts, xml in records(path, xml_safe=True):
        try:
            rep = from_event(event_details(rid, ts, xml))
        except (ValueError, SyntaxError):
            continue
        if rep is not None:
            out.append(rep)
    return out


def hexval(s):
    try:
        return int(s, 16)
    except (TypeError, ValueError):
        return None


def kernel_code(rep):
    code = hexval(rep.s(0))
    if code is None or not 0 < code <= 0xFFFFFFFF:
        return None
    return (code & ~0x10000000 or None) if rep.etype.casefold() == 'livekernelevent' else code


def fmt_t(t):
    return t.strftime('%d.%m.%Y %H:%M') if t and t != MIN else '??'


def kernel_block(reps, have):
    out = []
    groups = defaultdict(list)
    for r in reps:
        key = (r.etype, r.rid) if r.rid else (r.etype, id(r))
        groups[key].append(r)
    for rs in sorted(groups.values(), key=lambda group: min(r.t for r in group)):
        rep = next((r for r in rs if r.src == 'wer'), rs[0])
        p = [hexval(x) for x in rep.sigs[1:5]]
        live = rep.etype.casefold() == 'livekernelevent'
        base = kernel_code(rep)
        name = CODES.get(base, '')
        srcs = sorted({r.src for r in rs})
        out.append('   %s  %s %s%s' % (fmt_t(min(r.t for r in rs)), 'Live kernel event' if live else 'BSOD',
                                         '0x%X' % base if base is not None else 'unknown code',
                                         ('  ' + name) if name else ''))
        if len(p) == 4 and None not in p:
            out.append('         P1=%#x P2=%#x P3=%#x P4=%#x' % tuple(p))
        if base in (0x15E, 0x7C) and p and p[0] is not None:
            out.append('         NDIS: ' + NDIS_P1.get(p[0], 'unknown P1 subcode %#x' % p[0]))
            if p[0] == 0x25 and len(p) > 1 and p[1] is not None:
                out.append('         Operation: ' + NDIS_WD.get(p[1], 'unknown operation %#x' % p[1]))
        dmps = sorted({re.split(r'[\\/]', f)[-1] for r in rs for f in r.files if f.lower().endswith('.dmp')
                       and 'livekernelreports' in f.lower() or f.lower().endswith('.dmp') and 'minidump' in f.lower()})
        for d in dmps:
            out.append('         Dump %s: %s' % (d, 'captured' if d.lower() in have else 'missing from capture'))
        out.append('         Source: %s' % ' + '.join({'wer': 'WER folder', 'log': 'Application log (×%d)'
                                                          % sum(r.src == 'log' for r in rs)}[s] for s in srcs))
    return out


def report(root):
    werdir = os.path.join(root, 'wer')
    reps = [from_wer(os.path.join(werdir, f)) for f in sorted(os.listdir(werdir))
            if f.lower().endswith('.wer')] if os.path.isdir(werdir) else []
    n_wer = len(reps)
    log = from_journal(os.path.join(root, 'evt', 'Application.evtx'))
    have = set()
    for dp, _, fn in os.walk(root):
        have.update(f.lower() for f in fn)

    kernel = [r for r in reps + log if r.etype in KERNEL_TYPES]
    netdiag = [r for r in reps + log if r.etype.startswith('NetworkDiagnostics')]
    # Apps and noise: count each report once — prefer the .wer, add journal-only ones.
    seen = {r.rid for r in reps if r.rid}
    rest = [r for r in reps if r.etype not in KERNEL_TYPES and not r.etype.startswith('NetworkDiagnostics')]
    last_by_rid = {}
    for r in log:
        if r.etype in KERNEL_TYPES or r.etype.startswith('NetworkDiagnostics') or r.rid in seen:
            continue
        last_by_rid[r.rid or id(r)] = r
    rest += list(last_by_rid.values())

    out = ['WER: %d files in wer/, %d Application event 1001 records%s' % (
        n_wer, len(log), '' if records else ' (Application log reader unavailable)')]
    if kernel:
        out.append('Kernel reports (live kernel events and BSODs, UTC):')
        out += kernel_block(kernel, have)
    elif not reps and not log:
        # Check the saved WER setting when neither source contains reports.
        cs = os.path.join(root, 'info', 'crash-settings.txt')
        st = re.search(r'^WER state\s*:\s*(.+)$', open(cs, encoding='utf-8-sig', errors='replace').read(), re.M) \
            if os.path.isfile(cs) else None
        if st and st.group(1).startswith('OFF'):
            out.append('No WER reports captured. WER was disabled (%s). '
                       'Check dumps/ and System restart events for additional evidence.' % st.group(1).strip())
        elif st:
            out.append('No WER reports captured. Recorded WER state: %s' % st.group(1).strip())
        else:
            out.append('No WER reports captured. WER state is unknown (crash-settings.txt unavailable).')
    else:
        out.append('No live kernel or BSOD reports found in the captured WER data.')
    if netdiag:
        out.append('Network diagnostics (runs, first and last occurrence in UTC, reported cause):')
        g = defaultdict(list)
        for r in netdiag:
            g[(r.s(5, '?'), r.s(7), r.s(8).replace('//', '.').replace('/', '.'), r.s(3))].append(r.t)
        for (hc, drv, ver, hr), ts in sorted(g.items(), key=lambda i: min(i[1])):
            # Journal writes each run twice (queued, then sent) — count distinct minutes.
            runs = len({t.replace(second=0, microsecond=0) for t in ts})
            out.append('   %3d  %s to %s  %s%s, result %s' % (runs, fmt_t(min(ts)), fmt_t(max(ts)), hc,
                                                           ('  driver %s %s' % (drv, ver)).rstrip() if drv else '', hr or '?'))
    apps, other = defaultdict(list), defaultdict(int)
    for r in rest:
        if r.etype in ('APPCRASH', 'MoAppCrash', 'BEX', 'BEX64') or 'Hang' in r.etype:
            hang = 'Hang' in r.etype
            bex = r.etype.startswith('BEX')
            key = (r.s(0, '?'),
                   'hang' if hang else r.named(FAULT_MODULE, 3, '?'),
                   '' if hang else r.named(EXCEPTION_CODE, 7 if bex else 6))
            apps[key].append(r.t)
        else:
            other[r.etype] += 1
    if apps:
        out.append('Applications (reports, last date in UTC, application / module / code):')
        for (app, mod, exc), ts in sorted(apps.items(), key=lambda i: -len(i[1])):
            out.append('   %3d  %s  %s / %s%s' % (len(ts), fmt_t(max(ts))[:10], app[:60], mod,
                                                 (' / ' + exc) if exc else ''))
    if other:
        out.append('Other: ' + ', '.join('%s ×%d' % (k, n) for k, n in sorted(other.items(), key=lambda i: -i[1])))
    return out


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    for d in sys.argv[1:]:
        print('==', os.path.basename(os.path.normpath(d)))
        print('\n'.join(report(d)))
