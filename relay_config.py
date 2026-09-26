"""Validated relay limits loaded once at startup, so policy changes require a restart."""
from dataclasses import asdict, dataclass, fields
import os


@dataclass(frozen=True)
class Limits:
    max_members: int = 10
    max_message_bytes: int = 48000
    max_queued_per_recipient: int = 1000
    max_queued_messages: int = 10000
    max_queued_bytes: int = 64 * 1024 * 1024
    max_delivery_records: int = 100000
    max_invite_records: int = 10000
    max_frames_per_second: int = 100
    max_attachment_bytes: int = 8 * 1024 * 1024
    max_attachment_total_bytes: int = 128 * 1024 * 1024
    max_attachment_records: int = 10000
    max_attachments_per_sender: int = 32

    @classmethod
    def from_env(cls):
        # Reject typos/zero values instead of silently disabling resource protections.
        values = {}
        for field in fields(cls):
            name = 'MESH_' + field.name.upper()
            raw = os.getenv(name, str(field.default))
            try:
                value = int(raw)
            except ValueError:
                raise ValueError(f'{name} must be a positive integer') from None
            if value < 1 or value > 2**40:
                raise ValueError(f'{name} must be between 1 and {2**40}')
            values[field.name] = value
        if values['max_message_bytes'] > 48000:
            raise ValueError('MESH_MAX_MESSAGE_BYTES cannot exceed the 48000-byte protocol ceiling')
        if values['max_attachment_bytes'] > 8 * 1024 * 1024:
            raise ValueError('MESH_MAX_ATTACHMENT_BYTES cannot exceed the 8 MiB protocol ceiling')
        return cls(**values)

    def public(self):
        return asdict(self)


class PolicyError(ValueError):
    """A safe error shared by HTTP/WebSocket handlers; never contains credentials."""
    def __init__(self, code, text, *, status=409, retryable=False):
        super().__init__(text)
        self.code, self.text, self.status, self.retryable = code, text, status, retryable

    def detail(self):
        return {'code': self.code, 'text': self.text, 'retryable': self.retryable}
