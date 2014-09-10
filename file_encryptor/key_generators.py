from Crypto.Protocol import KDF
import hashlib
import hmac
import settings


def sha256_file(path):
    """Calculate sha256 hex digest of a file."""
    h = hashlib.sha256()

    with open(path) as f:
        for chunk in iter(lambda: f.read(settings.CHUNK_SIZE), b''):
            h.update(chunk)

    return h.hexdigest()

def hashed_passphrase(passphrase, salt, key_len, iteration_depth):
    """Deep hash the provided password. If no password is provided,
       the default passphrase is returned and the hash is never
       performed."""
    if passphrase is None:
        return settings.DEFAULT_PASSPHRASE
    return KDF.PBKDF2(passphrase, salt, key_len, iteration_depth)

def key_from_file(filename,
                  passphrase,
                  salt=settings.DEFAULT_SALT,
                  key_len=settings.DEFAULT_KEY_LEN,
                  iteration_depth=settings.DEFAULT_ITERATION_DEPTH):
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

    return hmac.new(hashed_passphrase(passphrase,
                                      salt,
                                      key_len,
                                      iteration_depth),
                    hexdigest,
                    hashlib.sha256).digest()
