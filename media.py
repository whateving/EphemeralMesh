"""Bounded image/audio metadata validation shared by sender and receiver."""
import re
import uuid

MAX_FILE_BYTES = 5 * 1024 * 1024
MIME_TYPES = {'image/png', 'image/jpeg', 'image/gif', 'image/webp',
              'audio/webm', 'audio/ogg', 'audio/wav', 'audio/mp4'}


def validate_file(raw, mime):
    mime = mime.split(';', 1)[0].lower()
    if not raw or len(raw) > MAX_FILE_BYTES or mime not in MIME_TYPES:
        raise ValueError('Use PNG, JPEG, GIF, WebP, or a voice recording up to 5 MiB')
    # Names never determine content type. Signature checks are not an antivirus
    # scanner or a promise every file can be decoded by every browser.
    signatures = {
        'image/png': raw.startswith(b'\x89PNG\r\n\x1a\n'),
        'image/jpeg': raw.startswith(b'\xff\xd8\xff'),
        'image/gif': raw.startswith((b'GIF87a', b'GIF89a')),
        'image/webp': raw[:4] == b'RIFF' and raw[8:12] == b'WEBP',
        'audio/webm': raw.startswith(b'\x1a\x45\xdf\xa3'),
        'audio/ogg': raw.startswith(b'OggS'),
        'audio/wav': raw[:4] == b'RIFF' and raw[8:12] == b'WAVE',
        'audio/mp4': raw[4:8] == b'ftyp',
    }
    if not signatures[mime]:
        raise ValueError('File contents do not match the selected media type')
    return mime


def safe_name(name):
    # The filename is only a label; it is never used as a filesystem path.
    return re.sub(r'[\x00-\x1f\x7f]', '', re.split(r'[/\\]', name)[-1])[:120] or 'attachment'


def validate_metadata(item):
    if not isinstance(item, dict):
        raise ValueError('Invalid attachment metadata')
    uuid.UUID(item['id'])
    if item['mime'] not in MIME_TYPES or not isinstance(item['name'], str) or len(item['name']) > 120:
        raise ValueError('Invalid attachment type/name')
    if isinstance(item['size'], bool) or not isinstance(item['size'], int) or not 0 < item['size'] <= MAX_FILE_BYTES:
        raise ValueError('Invalid attachment length')
    if not re.fullmatch('[0-9a-f]{64}', item['sha256']):
        raise ValueError('Invalid attachment digest')
    return item
