import base64
import binascii
import os
import string

from flask import Flask, jsonify, request
from flask_cors import CORS

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
CORS(app)

KDF_ITERATIONS = 600_000
SALT_LEN = 16
ASCII_LETTERS = frozenset(string.ascii_letters)

DECRYPT_FAILED = ("Decryption failed: the key is wrong, or the text is not valid "
                  "ciphertext for the selected algorithm.")


class CipherError(ValueError):
    pass


def derive_key(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def to_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def from_b64(token: str, min_len: int) -> bytes:
    cleaned = "".join(token.split())
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        raise CipherError("The input is not valid Base64 ciphertext for this algorithm.") from None
    if len(raw) < min_len:
        raise CipherError("The ciphertext is too short or incomplete for this algorithm.")
    return raw


def encrypt_aes_gcm(plaintext: str, key_phrase: str) -> str:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(12)
    key = derive_key(key_phrase, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    return to_b64(salt + nonce + encryptor.tag + ciphertext)


def decrypt_aes_gcm(ciphertext_b64: str, key_phrase: str) -> str:
    payload = from_b64(ciphertext_b64, SALT_LEN + 12 + 16)
    salt, nonce = payload[:16], payload[16:28]
    tag, ciphertext = payload[28:44], payload[44:]
    key = derive_key(key_phrase, salt)
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")


def _key_shifts(key: str, name: str) -> list:
    shifts = [ord(c.upper()) - 65 for c in key if c in ASCII_LETTERS]
    if not shifts:
        raise CipherError(name + " key must contain at least one letter (A-Z).")
    return shifts


def encrypt_vigenere(plaintext: str, key: str) -> str:
    shifts = _key_shifts(key, "Vigenere")
    out, n = [], 0
    for ch in plaintext:
        if ch in ASCII_LETTERS:
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base + shifts[n % len(shifts)]) % 26 + base))
            n += 1
        else:
            out.append(ch)
    return "".join(out)


def decrypt_vigenere(ciphertext: str, key: str) -> str:
    shifts = _key_shifts(key, "Vigenere")
    out, n = [], 0
    for ch in ciphertext:
        if ch in ASCII_LETTERS:
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base - shifts[n % len(shifts)]) % 26 + base))
            n += 1
        else:
            out.append(ch)
    return "".join(out)


def encrypt_aes_cbc(plaintext: str, key_phrase: str) -> str:
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(16)
    key = derive_key(key_phrase, salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return to_b64(salt + iv + ciphertext)


def decrypt_aes_cbc(ciphertext_b64: str, key_phrase: str) -> str:
    payload = from_b64(ciphertext_b64, SALT_LEN + 16 + 16)
    salt, iv, ciphertext = payload[:16], payload[16:32], payload[32:]
    if len(ciphertext) % 16 != 0:
        raise CipherError("The ciphertext is corrupted or incomplete (invalid block length).")
    key = derive_key(key_phrase, salt)

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise CipherError(DECRYPT_FAILED) from None
    return plaintext.decode("utf-8")


def _autokey(text: str, key: str, decrypt: bool) -> str:
    stream = _key_shifts(key, "Autokey")
    out, n = [], 0
    for ch in text:
        if ch in ASCII_LETTERS:
            base = 65 if ch.isupper() else 97
            idx = ord(ch) - base
            if decrypt:
                new = (idx - stream[n]) % 26
                stream.append(new)
            else:
                new = (idx + stream[n]) % 26
                stream.append(idx)
            out.append(chr(new + base))
            n += 1
        else:
            out.append(ch)
    return "".join(out)


def encrypt_autokey(plaintext: str, key: str) -> str:
    return _autokey(plaintext, key, decrypt=False)


def decrypt_autokey(ciphertext: str, key: str) -> str:
    return _autokey(ciphertext, key, decrypt=True)


def encrypt_aes_ctr(plaintext: str, key_phrase: str) -> str:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(16)
    key = derive_key(key_phrase, salt)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    return to_b64(salt + nonce + ciphertext)


def decrypt_aes_ctr(ciphertext_b64: str, key_phrase: str) -> str:
    payload = from_b64(ciphertext_b64, SALT_LEN + 16 + 1)
    salt, nonce, ciphertext = payload[:16], payload[16:32], payload[32:]
    key = derive_key(key_phrase, salt)
    decryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")


def _columnar_key(key: str) -> str:
    key = "".join(key.split())
    if len(key) < 2:
        raise CipherError("Columnar Transposition key must have at least 2 characters.")
    return key


def _columnar_order(key: str) -> list:
    return sorted(range(len(key)), key=lambda i: key[i].upper())


def encrypt_columnar(plaintext: str, key: str) -> str:
    key = _columnar_key(key)
    cols = len(key)
    columns = [plaintext[c::cols] for c in range(cols)]
    return "".join(columns[c] for c in _columnar_order(key))


def decrypt_columnar(ciphertext: str, key: str) -> str:
    key = _columnar_key(key)
    cols = len(key)
    base, extra = divmod(len(ciphertext), cols)
    lengths = [base + (1 if c < extra else 0) for c in range(cols)]

    columns = [""] * cols
    pos = 0
    for c in _columnar_order(key):
        columns[c] = ciphertext[pos:pos + lengths[c]]
        pos += lengths[c]

    rows = base + (1 if extra else 0)
    out = []
    for r in range(rows):
        for c in range(cols):
            if r < len(columns[c]):
                out.append(columns[c][r])
    return "".join(out)


def encrypt_chacha20(plaintext: str, key_phrase: str) -> str:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(12)
    key = derive_key(key_phrase, salt)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return to_b64(salt + nonce + ciphertext)


def decrypt_chacha20(ciphertext_b64: str, key_phrase: str) -> str:
    payload = from_b64(ciphertext_b64, SALT_LEN + 12 + 16)
    salt, nonce, ciphertext = payload[:16], payload[16:28], payload[28:]
    key = derive_key(key_phrase, salt)
    plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


_PLAYFAIR_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def _playfair_square(key: str):
    letters = [c.upper().replace("J", "I") for c in key if c in ASCII_LETTERS]
    if not letters:
        raise CipherError("Playfair key must contain at least one letter (A-Z).")
    square = list(dict.fromkeys(letters + list(_PLAYFAIR_ALPHABET)))
    positions = {ch: divmod(i, 5) for i, ch in enumerate(square)}
    return square, positions


def _playfair_letters(text: str, what: str) -> list:
    letters = [c.upper().replace("J", "I") for c in text if c in ASCII_LETTERS]
    if not letters:
        raise CipherError("The " + what + " must contain at least one letter (A-Z).")
    return letters


def _playfair_apply(pairs, square, positions, step: int) -> str:
    out = []
    for a, b in pairs:
        r1, c1 = positions[a]
        r2, c2 = positions[b]
        if r1 == r2:
            out.append(square[r1 * 5 + (c1 + step) % 5])
            out.append(square[r2 * 5 + (c2 + step) % 5])
        elif c1 == c2:
            out.append(square[((r1 + step) % 5) * 5 + c1])
            out.append(square[((r2 + step) % 5) * 5 + c2])
        else:
            out.append(square[r1 * 5 + c2])
            out.append(square[r2 * 5 + c1])
    return "".join(out)


def encrypt_playfair(plaintext: str, key: str) -> str:
    square, positions = _playfair_square(key)
    letters = _playfair_letters(plaintext, "text")

    pairs, i = [], 0
    while i < len(letters):
        a = letters[i]
        if i + 1 < len(letters) and letters[i + 1] != a:
            pairs.append((a, letters[i + 1]))
            i += 2
        else:
            pairs.append((a, "Q" if a == "X" else "X"))
            i += 1
    return _playfair_apply(pairs, square, positions, +1)


def decrypt_playfair(ciphertext: str, key: str) -> str:
    square, positions = _playfair_square(key)
    letters = _playfair_letters(ciphertext, "ciphertext")
    if len(letters) % 2 != 0:
        raise CipherError("Playfair ciphertext must contain an even number of letters.")
    pairs = [(letters[i], letters[i + 1]) for i in range(0, len(letters), 2)]
    return _playfair_apply(pairs, square, positions, -1)


def _fernet(key_phrase: str, salt: bytes) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(derive_key(key_phrase, salt)))


def encrypt_fernet(plaintext: str, key_phrase: str) -> str:
    salt = os.urandom(SALT_LEN)
    token = _fernet(key_phrase, salt).encrypt(plaintext.encode("utf-8")).decode("ascii")
    return base64.urlsafe_b64encode(salt).decode("ascii") + "." + token


def decrypt_fernet(ciphertext: str, key_phrase: str) -> str:
    cleaned = "".join(ciphertext.split())
    parts = cleaned.split(".")
    if len(parts) != 2:
        raise CipherError("The input is not a valid Fernet token produced by this tool.")
    try:
        salt = base64.urlsafe_b64decode(parts[0])
    except (binascii.Error, ValueError):
        raise CipherError("The input is not a valid Fernet token produced by this tool.") from None
    if len(salt) != SALT_LEN:
        raise CipherError("The input is not a valid Fernet token produced by this tool.")
    return _fernet(key_phrase, salt).decrypt(parts[1].encode("utf-8")).decode("utf-8")


CIPHERS = {
    "aes_cbc": (encrypt_aes_cbc, decrypt_aes_cbc),
    "aes_ctr": (encrypt_aes_ctr, decrypt_aes_ctr),
    "aes_gcm": (encrypt_aes_gcm, decrypt_aes_gcm),
    "autokey": (encrypt_autokey, decrypt_autokey),
    "chacha20": (encrypt_chacha20, decrypt_chacha20),
    "columnar": (encrypt_columnar, decrypt_columnar),
    "fernet": (encrypt_fernet, decrypt_fernet),
    "playfair": (encrypt_playfair, decrypt_playfair),
    "vigenere": (encrypt_vigenere, decrypt_vigenere),
}


def error_response(message: str, status: int = 400):
    return jsonify({"error": message}), status


@app.route("/api/<action>", methods=["POST"])
def process_request(action):
    if action not in ("encrypt", "decrypt"):
        return error_response("Invalid action.")

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("Request body must be valid JSON.")

    algorithm = data.get("algorithm")
    text = data.get("text")
    key = data.get("key")

    if not isinstance(algorithm, str) or not isinstance(text, str) or not isinstance(key, str) \
            or not algorithm or not text.strip() or not key.strip():
        return error_response("Missing algorithm, text, or key.")

    if algorithm not in CIPHERS:
        return error_response("Unsupported algorithm.")

    cipher_fn = CIPHERS[algorithm][0 if action == "encrypt" else 1]

    try:
        return jsonify({"result": cipher_fn(text, key)})
    except CipherError as exc:
        return error_response(str(exc))
    except (InvalidTag, InvalidToken, UnicodeDecodeError):
        return error_response(DECRYPT_FAILED)
    except Exception:
        app.logger.exception("Unexpected error while processing request")
        return error_response("An unexpected server error occurred.", 500)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
