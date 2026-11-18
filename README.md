# Anamnez

[Русский](README.ru.md)

Anamnez collects Windows diagnostic logs and turns them into an offline report.
It lists detected problems, counts separate incidents where the records can be
linked, and shows the source and recorded time of each event.

## Run on Windows

1. Extract `Anamnez-Windows-x64.zip` and double-click `diagnostics.bat`.
2. Choose `1` for Anamnez and approve the administrator prompt.
3. Open the capture at the path printed on the `RESULT:` line. Extract the
   `.7z` if present and open `health.html` in a browser. The same capture
   contains `health.txt`, `health.json`, and the original logs.

Target systems (x64): Windows 7 SP1 → Windows 11, including Windows 10.
It selects portable Python 3.8 on Windows 7 and 3.13 on Windows 10 and 11.
On Windows 7, install KB2533623 or a superseding update and the Universal C
Runtime before running the package. Collection and reporting work offline.

A capture normally goes in `evt\` on the drive the tool was launched from,
or in `C:\Install\evt\` when launched from the system drive or when the
launch drive has insufficient space. If 7-Zip is unavailable or packing fails,
the collector keeps the capture as a folder. If analysis fails, it keeps the
collected logs and records the failure in `00-journal.txt`.

## Read the report

Download the [sample health.html](examples/health.html) and open it in a browser.
It uses synthetic data.

The report checks for unexpected restarts, bugchecks, live kernel reports,
dump write failures, application crashes and hangs, selected storage errors,
and WHEA hardware errors. It shows each available drive's overall SMART
status from smartctl with the source file path. If smartctl could not
read a status, the report says it is unavailable.

The HTML shows critical findings open and warnings collapsed. Select a
warning to see its events. The report counts episodes, event records, and
WER files separately. When the clock is suspect, recorded times remain
visible and the 7-day and 30-day counts are unavailable. The time on a
Kernel-Power 41 record is when Windows logged the restart on the next boot.

The capture preserves dump files and startup entries for manual review.
Detailed dump analysis, startup entry assessment, and root-cause diagnosis
require further investigation.

| In the capture | Contents |
|---|---|
| `00-summary.txt`, `00-journal.txt`, `00-manifest.sha256` | Machine summary, collection log, and checksums for verifying the capture |
| `evt/`, `wer/`, `dumps/` | Event logs, Windows Error Reporting records, and available crash dumps within collection limits |
| `info/` | System, storage, network, startup, driver, and other diagnostic data |
| `files/` | Setup and servicing logs. Large `CBS.log` files are saved as the last 100,000,000 bytes, which can start mid-line. |

Available evidence depends on Windows settings, what the logs still retain,
and which collection steps succeed. Captures and reports can contain device
names, user names, serial numbers, event details, and other private data.

## Optional Autoruns

Anamnez collects basic startup data with Windows tools. To add a more
detailed list, download [Autoruns from Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns),
extract it, and place `autorunsc64.exe` in `anamnez\tools\autoruns\` inside
the extracted Anamnez package. The collector will find it on the next run.

## Build a local Windows package

Use Python 3. Copy the installed
[smartmontools 7.5](https://github.com/smartmontools/smartmontools/releases/tag/RELEASE_7_5)
directory to `vendor/smartmontools`, including `bin/smartctl.exe`,
`bin/drivedb.h`, and `doc/COPYING.txt`.

```sh
python3 scripts/anamnez/build_portable.py release --tools-dir vendor
```

Choose a new output directory. The builder downloads and verifies the
portable Python runtimes, 7-Zip, and the smartmontools source archive.
You can also supply the source archive as `vendor/smartmontools-7.5.tar.gz`.
The builder bundles licenses with the tools.

## Work with an existing capture

Generate a report from an extracted capture in a new directory.

```sh
python3 scripts/anamnez/health.py capture --output report
```

To read a `.7z` directly, make `7z` or `7zz` available on your PATH.
Run the tests with Python 3 from the source directory.

```sh
python3 -m unittest discover -s tests
```
