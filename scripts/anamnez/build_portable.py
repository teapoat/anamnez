#!/usr/bin/env python3
"""Build one portable Windows Anamnez kit from pinned upstream binaries."""

import argparse
from hashlib import sha256
from io import BytesIO
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from urllib.request import urlopen
from zipfile import ZIP_DEFLATED, ZipFile


HERE = Path(__file__).resolve().parent
KIT_NAME = 'Anamnez-Windows-x64.zip'
RUNTIMES = (
    ('3.13.17', '9e35319bffedab8b36ad44d8f377cb4f1733bcec257a0b6d04d94f01486ddb38'),
    ('3.8.10', 'abbe314e9b41603dde0a823b76f5bbbe17b3de3e5ac4ef06b759da5466711271'),
)
SEVEN_ZIP_URLS = (
    'https://github.com/ip7z/7zip/releases/download/26.06/7zr.exe',
    'https://www.7-zip.org/a/7zr.exe',
)
SEVEN_ZIP_HASH = '256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282'
SMART_SOURCE = 'smartmontools-7.5.tar.gz'
SMART_SOURCE_URLS = (
    'https://github.com/smartmontools/smartmontools/releases/download/RELEASE_7_5/smartmontools-7.5.tar.gz',
    'https://downloads.sourceforge.net/project/smartmontools/smartmontools/7.5/smartmontools-7.5.tar.gz',
)
SMART_SOURCE_HASH = '690b83ca331378da9ea0d9d61008c4b22dde391387b9bbad7f29387f2595f76e'


def download_verified(urls, expected):
    errors = []
    for url in urls:
        try:
            with urlopen(url, timeout=30) as response:
                data = response.read(32 * 1024 * 1024)
            if sha256(data).hexdigest() == expected:
                return data
            errors.append(f'{url}: SHA-256 mismatch')
        except OSError as error:
            errors.append(f'{url}: {error}')
    raise ValueError('\n'.join(errors))


def add_runtime(out, runtime, directory):
    with ZipFile(BytesIO(runtime)) as python:
        for member in python.infolist():
            path = PurePosixPath(member.filename)
            if member.is_dir() or path.name != member.filename or '\\' in member.filename:
                raise ValueError(f'Unexpected entry in the upstream Python ZIP: {member.filename}')
            out.writestr(directory + '/' + member.filename, python.read(member))


def build_kit(output, tools_dir):
    if output.exists() or output.is_symlink():
        raise ValueError('Choose a new output folder')
    smart_dir = tools_dir / 'smartmontools'
    smart = {(smart_dir / name).name: (smart_dir / name).read_bytes()
             for name in ('bin/smartctl.exe', 'bin/drivedb.h', 'doc/COPYING.txt')}
    source_path = tools_dir / SMART_SOURCE
    smart_source = source_path.read_bytes() if source_path.is_file() else download_verified(
        SMART_SOURCE_URLS, SMART_SOURCE_HASH)
    output.parent.mkdir(parents=True, exist_ok=True)
    seven_zip = download_verified(SEVEN_ZIP_URLS, SEVEN_ZIP_HASH)
    with TemporaryDirectory(prefix='.anamnez-kit-', dir=output.parent) as temp:
        stage = Path(temp) / 'kit'
        stage.mkdir()
        with ZipFile(stage / KIT_NAME, 'w', compression=ZIP_DEFLATED) as out:
            out.write(HERE.parents[1] / 'LICENSE', 'LICENSE')
            out.write(HERE.parent / 'diagnostics.bat', 'diagnostics.bat')
            for name in ('anamnez.bat', 'anamnez.ps1', 'health.py', 'health_input.py', 'wer_info.py'):
                out.write(HERE / name, 'anamnez/' + name)
            out.write(HERE.parent / 'evtx_read.py', 'anamnez/evtx_read.py')
            out.writestr('anamnez/tools/7zip/7zr.exe', seven_zip)
            for name, data in smart.items():
                out.writestr('anamnez/tools/smartmontools/' + name, data)
            out.writestr('anamnez/tools/smartmontools/' + SMART_SOURCE, smart_source)
            start = [
                'Anamnez portable for Windows 7 SP1, Windows 10 and Windows 11 (x64).',
                '',
                'Extract the ZIP and double-click diagnostics.bat. Choose 1, then approve UAC.',
                'Open the capture at the RESULT path. Start with health.html.',
                'Raw logs, health.txt and health.json are in the same capture.',
                '',
                'Python is selected automatically for your Windows version.',
                'On Windows 7, the bundled Python needs KB2533623 (or its replacement) and Universal C Runtime.',
                '',
                'Optional: download Autoruns from https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns',
                'and put autorunsc64.exe in anamnez\\tools\\autoruns for a more detailed startup list.',
                '',
            ]
            for version, digest in RUNTIMES:
                python_url = f'https://www.python.org/ftp/python/{version}/python-{version}-embed-amd64.zip'
                directory = 'anamnez/tools/python/' + version.rsplit('.', 1)[0]
                add_runtime(out, download_verified((python_url,), digest), directory)
                start += [f'Bundled Python {version}: {python_url}', f'Python license: {directory}/LICENSE.txt']
            start.append('Bundled 7zr.exe: LZMA SDK (public domain), https://www.7-zip.org/sdk.html')
            start.append('Bundled smartctl 7.5: see COPYING.txt and source archive in anamnez/tools/smartmontools.')
            out.writestr('START.txt', '\r\n'.join(start) + '\r\n')
        stage.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='New folder for the Windows ZIP')
    parser.add_argument('--tools-dir', required=True, type=Path,
                        help='Folder containing the installed smartmontools 7.5 folder')
    args = parser.parse_args()
    try:
        build_kit(args.output.absolute(), args.tools_dir)
    except (OSError, ValueError) as error:
        parser.exit(2, f'Anamnez: {error}\n')
    print(f'Kit: {args.output.absolute() / KIT_NAME}')


if __name__ == '__main__':
    main()
