"""Private key decoding.

The browser sends the private key base64-encoded (the base64 of the whole
key file, e.g. `base64 -w0 ~/.ssh/id_ed25519`). The key only ever lives in
memory for the duration of the connection handshake.
"""

from __future__ import annotations

import base64
import binascii
from typing import Optional

import asyncssh

MAX_KEY_B64_LEN = 64 * 1024  # generous; real keys are a few KB at most


class KeyError_(ValueError):
    """Raised for any problem with the supplied key. Message is safe to show the user.

    ``code`` is a stable machine-readable error code (see app/errors.py).
    """

    code = "key_invalid"


class KeyInvalid(KeyError_):
    code = "key_invalid"


class KeyPassphraseRequired(KeyError_):
    code = "key_passphrase_required"


class KeyPassphraseWrong(KeyError_):
    code = "key_passphrase_wrong"


def decode_private_key(key_b64: str, passphrase: Optional[str] = None) -> asyncssh.SSHKey:
    if not isinstance(key_b64, str) or not key_b64.strip():
        raise KeyInvalid("Private key is empty")
    if len(key_b64) > MAX_KEY_B64_LEN:
        raise KeyInvalid("Private key is too large")

    text = key_b64.strip()
    if text.startswith("-----BEGIN"):
        # Convenience: accept a raw PEM/OpenSSH key pasted as-is.
        raw = text.encode("utf-8")
    else:
        try:
            raw = base64.b64decode("".join(text.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise KeyInvalid("Private key is not valid base64") from exc

    try:
        return asyncssh.import_private_key(raw, passphrase or None)
    except asyncssh.KeyEncryptionError as exc:
        if passphrase:
            raise KeyPassphraseWrong("Wrong passphrase for the private key") from exc
        raise KeyPassphraseRequired("The private key is encrypted: a passphrase is required") from exc
    except (asyncssh.KeyImportError, ValueError) as exc:
        if "passphrase" in str(exc).lower():
            if passphrase:
                raise KeyPassphraseWrong("Wrong passphrase for the private key") from exc
            raise KeyPassphraseRequired(
                "The private key is encrypted: a passphrase is required") from exc
        raise KeyInvalid("Unsupported or invalid private key format") from exc
    finally:
        del raw


def key_fingerprint(key: asyncssh.SSHKey) -> str:
    """SHA256 fingerprint of the public half (safe to log)."""
    return key.convert_to_public().get_fingerprint("sha256")
