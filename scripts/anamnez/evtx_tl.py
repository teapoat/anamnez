#!/usr/bin/env python3
"""Compact one-line-per-event timeline of an .evtx, in RECORD order.

    python3 scripts/anamnez/evtx_tl.py <file.evtx> [regex over XML] [-s 'skip regex over "Provider ID"']
                                       [-r FROM-TO record ids] [-w width] [-z hours, default 0] [--hist]

Record order preserves the sequence when a clock change shifts timestamps.
Backward clock steps over 60 seconds are marked with '!! clock'.
UTF-16 hex strings in event data are decoded to text. Times are shown in UTC by default.
--hist prints counts per provider+id with first/last time instead of the timeline.
"""
import argparse
import collections
import datetime
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from evtx_read import records  # noqa: E402

HEX16 = re.compile(r'(?:[0-9a-fA-F]{4})+')


def decode(v):
    """UTF-16LE hex blob -> text; anything else is returned as is."""
    if len(v) >= 8 and HEX16.fullmatch(v):
        try:
            s = bytes.fromhex(v).decode('utf-16le')
            if all(c == '\x00' or c.isprintable() for c in s):
                return s.replace('\x00', ' | ').strip(' |')
        except (ValueError, UnicodeDecodeError):
            pass
    return v


def parse(xml):
    prov = re.search(r'Provider Name="([^"]*)"', xml)
    eid = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
    lvl = re.search(r'<Level>(\d+)</Level>', xml)
    body = xml.split('</System>', 1)[-1]
    out = []
    for k, v in re.findall(r'<Data(?: Name="([^"]*)")?>(.*?)</Data>', body, re.S):
        if v:
            v = decode(v)
            out.append('%s=%s' % (k, v) if k else v)
    return ((prov.group(1) if prov else '?').replace('Microsoft-Windows-', ''),
            eid.group(1) if eid else '?', lvl.group(1) if lvl else '?',
            re.sub(r'\s+', ' ', '; '.join(out)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('evtx')
    ap.add_argument('pattern', nargs='?')
    ap.add_argument('-s', '--skip')
    ap.add_argument('-r', '--range')
    ap.add_argument('-w', '--width', type=int, default=220)
    ap.add_argument('-z', '--tz', type=float, default=0.0, help='Hours to add to UTC timestamps (default: 0)')
    ap.add_argument('--hist', action='store_true')
    a = ap.parse_args()
    pat = re.compile(a.pattern, re.I) if a.pattern else None
    skip = re.compile(a.skip, re.I) if a.skip else None
    lo, hi = (int(x) for x in a.range.split('-')) if a.range else (0, 1 << 62)
    shift = datetime.timedelta(hours=a.tz)

    rows = []
    for rid, ts, xml in records(a.evtx):
        t = ts + shift if ts is not None else None
        rows.append((rid, t, xml))
    rows.sort(key=lambda r: r[0])

    hist, first, last = collections.Counter(), {}, {}
    prev = None
    for rid, t, xml in rows:
        # clock steps are judged on ALL records, before any filtering
        jump = prev is not None and t is not None and (prev - t).total_seconds() > 60
        if jump and not a.hist:
            print('!! clock stepped back %s -> %s at record %d: earlier stamps are shifted'
                  % (prev.strftime('%m-%d %H:%M:%S'), t.strftime('%m-%d %H:%M:%S'), rid))
        if t is not None:
            prev = t
        if not lo <= rid <= hi or (pat and not pat.search(xml)):
            continue
        prov, eid, lvl, txt = parse(xml)
        if skip and skip.search('%s %s' % (prov, eid)):
            continue
        if a.hist:
            k = (prov, eid, lvl)
            hist[k] += 1
            if t is not None:
                first.setdefault(k, t)
                last[k] = t
        else:
            stamp = t.strftime('%m-%d %H:%M:%S') if t is not None else 'time unknown'
            print('%6d  %s  L%s  %s %s  %s' % (rid, stamp, lvl, prov, eid, txt[:a.width]))
    for k, n in hist.most_common():
        window = ('%s .. %s' % (first[k].strftime('%m-%d %H:%M'), last[k].strftime('%m-%d %H:%M'))
                  if k in first else 'time unknown')
        print('%5d  L%s  %-42s %-6s %s' % (n, k[2], k[0], k[1], window))


if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        pass
