"""Password-encrypted, versioned profile backups. Stop the client before using this CLI."""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import getpass
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b'EMBACKUP1'
MAX_BYTES = 256 * 1024 * 1024


def derive(password, salt):
    # Salted, memory-hard password derivation; parameters are fixed and cannot be
    # increased by an attacker modifying a backup header to exhaust system memory.
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))


@contextmanager
def profile_lock(directory):
    if not (directory / 'identity.pem').is_file() or not (directory / 'client.db').is_file():
        raise ValueError('Profile does not contain an identity and client database')
    with (directory / 'profile.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Stop the client before backing up this profile') from None
        yield


def export_profile(directory, output, password):
    directory, output = Path(directory), Path(output)
    if len(password) < 12:
        raise ValueError('Use a backup password of at least 12 characters')
    with profile_lock(directory), tempfile.TemporaryDirectory() as scratch:
        snapshot = Path(scratch) / 'snapshot.db'
        # SQLite backup includes committed WAL contents; copying client.db alone may not.
        source = sqlite3.connect(f'file:{directory.resolve() / "client.db"}?mode=ro', uri=True)
        destination = sqlite3.connect(snapshot)
        try:
            source.backup(destination)
        finally:
            source.close(); destination.close()
        if snapshot.stat().st_size > MAX_BYTES // 2:
            raise ValueError('Profile exceeds the 128 MiB backup snapshot limit')
        payload = json.dumps({'version': 1, 'identity': directory.joinpath('identity.pem').read_text(),
                              'database': base64.b64encode(snapshot.read_bytes()).decode()}).encode()
        salt, nonce = os.urandom(16), os.urandom(12)
        header = MAGIC + salt + nonce
        encrypted = header + AESGCM(derive(password, salt)).encrypt(nonce, payload, header)
        # Refuse to overwrite an existing backup, and make new backups owner-readable only.
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encrypted); stream.flush(); os.fsync(stream.fileno())


def restore_profile(backup, directory, password):
    backup, directory = Path(backup), Path(directory)
    if directory.exists():
        raise ValueError('Restore requires a new profile directory; existing profiles are never overwritten')
    if backup.stat().st_size > MAX_BYTES:
        raise ValueError('Backup file exceeds the size limit')
    data = backup.read_bytes()
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 44:
        raise ValueError('Unsupported or truncated backup')
    salt, nonce = data[9:25], data[25:37]
    try:
        clear = AESGCM(derive(password, salt)).decrypt(nonce, data[37:], data[:37])
        payload = json.loads(clear)
        if payload['version'] != 1:
            raise ValueError('Unsupported backup version')
        identity = payload['identity'].encode()
        # Restored identities must use the same curve as the client protocol.
        key = serialization.load_pem_private_key(identity, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP384R1):
            raise ValueError('Unsupported identity key')
        database = base64.b64decode(payload['database'], validate=True)
    except (InvalidTag, KeyError, TypeError, UnicodeError, ValueError):
        raise ValueError('Wrong password, damaged backup, or unsupported profile') from None
    with tempfile.TemporaryDirectory(dir=directory.parent) as scratch:
        snapshot = Path(scratch) / 'client.db'
        snapshot.write_bytes(database)
        conn = sqlite3.connect(snapshot)
        try:
            conn.execute('PRAGMA trusted_schema=OFF')
            if conn.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('Backup database failed integrity verification')
            for table in ('settings', 'peers', 'messages', 'inbox', 'outbox'):
                row = conn.execute("SELECT type FROM sqlite_master WHERE name=?", (table,)).fetchone()
                if not row or row[0] != 'table':
                    raise ValueError('Backup is missing required profile tables')
        finally:
            conn.close()
        # Create the destination exclusively only after authentication and validation.
        directory.mkdir(mode=0o700)
        for name, content in (('identity.pem', identity), ('client.db', database)):
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('export', 'restore'))
    parser.add_argument('--profile', required=True)
    parser.add_argument('--file', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', args.profile):
        parser.error('Invalid profile name')
    root = Path(__file__).parent / '.mesh'
    root.mkdir(mode=0o700, exist_ok=True)
    os.umask(0o077)
    password = getpass.getpass('Backup password: ')
    if args.action == 'export' and password != getpass.getpass('Confirm password: '):
        parser.error('Passwords do not match')
    try:
        if args.action == 'export':
            export_profile(root / args.profile, args.file, password)
        else:
            restore_profile(args.file, root / args.profile, password)
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.error(str(exc))
    print(f'Profile {args.action} completed. Keep the backup password separate from the file.')


if __name__ == '__main__':
    main()
