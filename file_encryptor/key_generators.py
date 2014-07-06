from Crypto.Protocol import KDF
import hashlib
import settings


def sha256_file(path):
    """Calculate sha256 hex digest of a file."""
    h = hashlib.sha256()

    with open(path) as f:
        for chunk in iter(lambda: f.read(settings.CHUNK_SIZE), b''):
            h.update(chunk)

    return h.hexdigest()

def key_from_file(filename,
                  passphrase=None,
                  salt=None,
                  key_len=None,
                  iteration_depth=None):
    """Calculate convergent encryption key.

    This takes a filename and an optional passphrase.
    If no passphrase is given, a default is used.
    Using the default passphrase means you will be
    vulnerable to confirmation attacks and
    learn-partial-information attacks.

    Multiple arguments are also available for configuring
    the employed KDF; including salt, key_len, and
    iteration_depth. Currently employed is PBKDF2 from
    PKCS #5, v2

    """
    hexdigest = sha256_file(filename)

    if passphrase is None:
        passphrase = settings.DEFAULT_HMAC_PASSPHRASE

    if salt is None:
        salt = settings.DEFAULT_SALT

    if key_len is None:
        key_len = settings.DEFAULT_KEY_LEN

    if iteration_depth is None:
        iteration_depth = settings.DEFAULT_ITERATION_DEPTH

    return KDF.PBKDF2(passphrase + hexdigest,
                      salt,
                      key_len,
                      iteration_depth)
