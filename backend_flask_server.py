import base64
import os
import math
from flask import Flask, request, jsonify
from flask_cors import CORS

# Cryptography modules for modern symmetric ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)
# Enable CORS for all routes so the frontend can interact without browser restrictions
CORS(app)

# ==========================================
# HELPER FUNCTIONS (KEY DERIVATION)
# ==========================================

def derive_key(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    """Derive a fixed-size byte key from an arbitrary string using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passphrase.encode('utf-8'))

# ==========================================
# MODERN CIPHER IMPLEMENTATIONS
# ==========================================

def encrypt_aes_gcm(plaintext: str, key_phrase: str) -> str:
    salt = os.urandom(16)
    nonce = os.urandom(12)i
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    # Payload format: salt + nonce + tag + ciphertext
    payload = salt + nonce + encryptor.tag + ciphertext
    return base64.b64encode(payload).decode('utf-8')

def decrypt_aes_gcm(ciphertext_b64: str, key_phrase: str) -> str:
    payload = base64.b64decode(ciphertext_b64.encode('utf-8'))
    salt = payload[:16]
    nonce = payload[16:28]
    tag = payload[28:44]
    ciphertext = payload[44:]
    key = derive_key(key_phrase, salt, 32)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

def encrypt_aes_cbc(plaintext: str, key_phrase: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(key_phrase, salt, 32)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    payload = salt + iv + ciphertext
    return base64.b64encode(payload).decode('utf-8')

def decrypt_aes_cbc(ciphertext_b64: str, key_phrase: str) -> str:
    payload = base64.b64decode(ciphertext_b64.encode('utf-8'))
    salt = payload[:16]
    iv = payload[16:32]
    ciphertext = payload[32:]
    key = derive_key(key_phrase, salt, 32)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8')

def encrypt_aes_ctr(plaintext: str, key_phrase: str) -> str:
    salt = os.urandom(16)
    nonce = os.urandom(16)
    key = derive_key(key_phrase, salt, 32)
    
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    
    payload = salt + nonce + ciphertext
    return base64.b64encode(payload).decode('utf-8')

def decrypt_aes_ctr(ciphertext_b64: str, key_phrase: str) -> str:
    payload = base64.b64decode(ciphertext_b64.encode('utf-8'))
    salt = payload[:16]
    nonce = payload[16:32]
    ciphertext = payload[32:]
    key = derive_key(key_phrase, salt, 32)
    
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

def encrypt_chacha20(plaintext: str, key_phrase: str) -> str:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(key_phrase, salt, 32)
    
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    
    payload = salt + nonce + ciphertext
    return base64.b64encode(payload).decode('utf-8')

def decrypt_chacha20(ciphertext_b64: str, key_phrase: str) -> str:
    payload = base64.b64decode(ciphertext_b64.encode('utf-8'))
    salt = payload[:16]
    nonce = payload[16:28]
    ciphertext = payload[28:]
    key = derive_key(key_phrase, salt, 32)
    
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

def encrypt_fernet(plaintext: str, key_phrase: str) -> str:
    salt = b'fernet_fixed_salt'
    key_32bytes = derive_key(key_phrase, salt, 32)
    fernet_key = base64.urlsafe_b64encode(key_32bytes)
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode('utf-8')).decode('utf-8')

def decrypt_fernet(ciphertext: str, key_phrase: str) -> str:
    salt = b'fernet_fixed_salt'
    key_32bytes = derive_key(key_phrase, salt, 32)
    fernet_key = base64.urlsafe_b64encode(key_32bytes)
    f = Fernet(fernet_key)
    return f.decrypt(ciphertext.encode('utf-8')).decode('utf-8')

# ==========================================
# CLASSICAL CIPHER IMPLEMENTATIONS
# ==========================================

def encrypt_autokey(plaintext: str, key: str) -> str:
    key_clean = ''.join(filter(str.isalpha, key)).upper()
    if not key_clean:
        raise ValueError("Key must contain alphabetic characters.")
    text_clean = ''.join(filter(str.isalpha, plaintext)).upper()
    full_key = key_clean + text_clean
    result = []
    for i, char in enumerate(text_clean):
        shift = ord(full_key[i]) - 65
        result.append(chr((ord(char) - 65 + shift) % 26 + 65))
    return "".join(result)

def decrypt_autokey(ciphertext: str, key: str) -> str:
    key_clean = ''.join(filter(str.isalpha, key)).upper()
    if not key_clean:
        raise ValueError("Key must contain alphabetic characters.")
    cipher_clean = ''.join(filter(str.isalpha, ciphertext)).upper()
    result = []
    current_key = list(key_clean)
    for i, char in enumerate(cipher_clean):
        shift = ord(current_key[i]) - 65
        decrypted_char = chr((ord(char) - 65 - shift) % 26 + 65)
        result.append(decrypted_char)
        current_key.append(decrypted_char)
    return "".join(result)

def encrypt_columnar(plaintext: str, key: str) -> str:
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    cols = len(key)
    rows = math.ceil(len(plaintext) / cols)
    padded = plaintext.ljust(rows * cols, 'X')
    matrix = [padded[i*cols:(i+1)*cols] for i in range(rows)]
    ciphertext = ""
    for c in key_order:
        for r in range(rows):
            ciphertext += matrix[r][c]
    return ciphertext

def decrypt_columnar(ciphertext: str, key: str) -> str:
    cols = len(key)
    if cols == 0:
        raise ValueError("Key cannot be empty.")
    rows = len(ciphertext) // cols
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    matrix = [['' for _ in range(cols)] for _ in range(rows)]
    
    idx = 0
    for c in key_order:
        for r in range(rows):
            if idx < len(ciphertext):
                matrix[r][c] = ciphertext[idx]
                idx += 1
    return "".join("".join(row) for row in matrix).rstrip('X')

def create_playfair_square(key: str):
    key_clean = "".join(dict.fromkeys((key + "ABCDEFGHIKLMNOPQRSTUVWXYZ").upper()))
    key_clean = [c for c in key_clean if c.isalpha() and c != 'J']
    return [key_clean[i:i+5] for i in range(0, 25, 5)]

def find_position(square, char):
    for r in range(5):
        for c in range(5):
            if square[r][c] == char:
                return r, c
    return 0, 0

def encrypt_playfair(plaintext: str, key: str) -> str:
    square = create_playfair_square(key)
    text = plaintext.upper().replace('J', 'I')
    text = "".join([c for c in text if c.isalpha()])
    
    i = 0
    prepared = []
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            prepared.extend([a, 'X'])
            i += 1
        else:
            prepared.extend([a, b])
            i += 2
            
    ciphertext = []
    for i in range(0, len(prepared), 2):
        r1, c1 = find_position(square, prepared[i])
        r2, c2 = find_position(square, prepared[i+1])
        if r1 == r2:
            ciphertext.append(square[r1][(c1 + 1) % 5])
            ciphertext.append(square[r2][(c2 + 1) % 5])
        elif c1 == c2:
            ciphertext.append(square[(r1 + 1) % 5][c1])
            ciphertext.append(square[(r2 + 1) % 5][c2])
        else:
            ciphertext.append(square[r1][c2])
            ciphertext.append(square[r2][c1])
    return "".join(ciphertext)

def decrypt_playfair(ciphertext: str, key: str) -> str:
    square = create_playfair_square(key)
    text = "".join([c for c in ciphertext.upper() if c.isalpha()])
    plaintext = []
    for i in range(0, len(text), 2):
        r1, c1 = find_position(square, text[i])
        r2, c2 = find_position(square, text[i+1])
        if r1 == r2:
            plaintext.append(square[r1][(c1 - 1) % 5])
            plaintext.append(square[r2][(c2 - 1) % 5])
        elif c1 == c2:
            plaintext.append(square[(r1 - 1) % 5][c1])
            plaintext.append(square[(r2 - 1) % 5][c2])
        else:
            plaintext.append(square[r1][c2])
            plaintext.append(square[r2][c1])
    return "".join(plaintext)

def encrypt_vigenere(plaintext: str, key: str) -> str:
    key_clean = [ord(c.upper()) - 65 for c in key if c.isalpha()]
    if not key_clean:
        raise ValueError("Key must contain alphabetic characters.")
    result = []
    key_idx = 0
    for char in plaintext:
        if char.isalpha():
            shift = key_clean[key_idx % len(key_clean)]
            base = 65 if char.isupper() else 97
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return "".join(result)

def decrypt_vigenere(ciphertext: str, key: str) -> str:
    key_clean = [ord(c.upper()) - 65 for c in key if c.isalpha()]
    if not key_clean:
        raise ValueError("Key must contain alphabetic characters.")
    result = []
    key_idx = 0
    for char in ciphertext:
        if char.isalpha():
            shift = key_clean[key_idx % len(key_clean)]
            base = 65 if char.isupper() else 97
            result.append(chr((ord(char) - base - shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return "".join(result)

# ==========================================
# API ROUTE HANDLERS
# ==========================================

CIPHERS = {
    'aes_cbc': (encrypt_aes_cbc, decrypt_aes_cbc),
    'aes_ctr': (encrypt_aes_ctr, decrypt_aes_ctr),
    'aes_gcm': (encrypt_aes_gcm, decrypt_aes_gcm),
    'autokey': (encrypt_autokey, decrypt_autokey),
    'chacha20': (encrypt_chacha20, decrypt_chacha20),
    'columnar': (encrypt_columnar, decrypt_columnar),
    'fernet': (encrypt_fernet, decrypt_fernet),
    'playfair': (encrypt_playfair, decrypt_playfair),
    'vigenere': (encrypt_vigenere, decrypt_vigenere)
}

@app.route('/api/<action>', methods=['POST'])
def process_request(action):
    if action not in ['encrypt', 'decrypt']:
        return jsonify({'error': 'Invalid action'}), 400

    data = request.get_json() or {}
    algorithm = data.get('algorithm')
    text = data.get('text')
    key = data.get('key')

    if not algorithm or not text or not key:
        return jsonify({'error': 'Missing algorithm, text, or key'}), 400

    if algorithm not in CIPHERS:
        return jsonify({'error': 'Unsupported algorithm'}), 400

    try:
        cipher_fn = CIPHERS[algorithm][0] if action == 'encrypt' else CIPHERS[algorithm][1]
        result = cipher_fn(text, key)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    # Runs backend on http://127.0.0.1:5000
    app.run(host='127.0.0.1', port=5000, debug=True)