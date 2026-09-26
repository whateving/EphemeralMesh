"""Check Git's staged file contents for private artifacts and common credential markers."""
from pathlib import PurePosixPath
import re
import subprocess
import sys


def violations(name, data):
    path = PurePosixPath(name)
    # Reject private/generated files even when someone bypasses .gitignore with git add -f.
    private_dirs = {'.mesh', '.git', 'venv', '.venv', '__pycache__', 'backups', 'dist', 'node_modules', '.local-notes'}
    private_suffixes = ('.db', '.db-wal', '.db-shm', '.sqlite', '.sqlite3', '.pem', '.key',
                        '.sqlite-wal', '.sqlite-shm', '.sqlite3-wal', '.sqlite3-shm',
                        '.embackup', '.pcap', '.pcapng', '.log', '.zip', '.tar.gz', '.pyc')
    if (private_dirs.intersection(path.parts) or path.name.endswith(private_suffixes)
            or (path.name.startswith('.env') and path.name != '.env.example')
            or path.name in {'.DS_Store', 'admin-smoke-report.txt'}):
        yield 'private/generated file path'
    # Report rule names and filenames only; never echo matching credential bytes.
    patterns = {
        'private key material': rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
        'GitHub credential': rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b',
        'AWS access key': rb'\bAKIA[A-Z0-9]{16}\b',
        'personal macOS path': rb'/Users/[A-Za-z0-9_.-]+/',
        'credential-bearing database URL': rb'postgres(?:ql)?://[^\s:/]+:[^\s@]+@',
    }
    for label, pattern in patterns.items():
        if re.search(pattern, data):
            yield label


def main():
    try:
        names = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
        names = [name for name in names if name]
        if not names:
            print('FAIL: no staged/tracked files; stage the intended source first')
            return 1
        failures = []
        for name in names:
            # Scan index blobs, not working-tree files, to match the content of a commit.
            data = subprocess.check_output(['git', 'show', ':' + name])
            failures.extend((name, reason) for reason in violations(name, data))
        for name, reason in failures:
            print(f'FAIL {name}: {reason}')
        if failures:
            return 1
        print(f'PASS: {len(names)} Git index files checked for private artifacts and common secret markers')
        print('This guard is not an exhaustive secret scanner; review git diff --cached before publishing.')
        return 0
    except subprocess.CalledProcessError:
        print('FAIL: cannot inspect Git index')
        return 1


if __name__ == '__main__':
    sys.exit(main())
