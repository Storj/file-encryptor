file-encryptor
==============

Convergent encryption focused on encryption and decryption of files.
Contains helper methods to encrypt and decrypt files inline (no extra
space required) and to stream decryption.

#### Usage

Here's an example to encrypt a file inline using convergent encryption:

```python
import file_encryptor.convergence

key = convergence.encrypt_inline_file("/path/to/file", None)
```

You can also specify a passphrase:

```python
import file_encryptor.convergence

key = convergence.encrypt_inline_file("/path/to/file", "rainbow dinosaur secret")
```

To decrypt a file inline, you need the key that was returned by the encrypt
method:

```python
import file_encryptor.convergence

key = convergence.encrypt_inline_file("/path/to/file", "rainbow dinosaur secret")

convergence.decrypt_inline_file("/path/to/file", key)
```

The reason why you cannot use the passphrase directly is because the key is
derived from both the passphrase and the sha256 of the original file.

For streaming applications, you can decrypt a file with a generator:

```python
for chunk in convergence.decrypt_generator("/path/to/file", key):
    do_something_with_chunk(chunk)
```


#### Cryptoconcerns

The key generation mechanism is the following:

```
key = HMAC-SHA256(pbkdf2(passphrase), hex(SHA256(file-contents)))
```

If no passphrase is given, a default is used. If a passphrase is given
PBKDF2 is employed to derive a key from it.

PBKDF2 is configured by default to produce a key 16 octets in length,
uses an iteration depth of 2000, and employs HMAC-SHA1 as the prng.

The file itself is encrypted using AES128-CTR, from pycryptopp. We're not
specifying any IV, thinking that for convergent encryption that is the right
thing to do.

#### Testing

Tests were implemented using unittest, so the standard way of executing those is:

```
python -munittest discover file_encryptor/
```
