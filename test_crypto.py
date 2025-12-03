import json
import base64
import hashlib
import urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Configuration from prompt
SALT_FIXO = b"AMIGO_SECRETO_SALT_2025" # Defining a fixed salt as requested
ITERATIONS = 10000
KEY_SIZE = 32 # 256 bits

def get_key(pin: str) -> bytes:
    """
    Derives a 32-byte key from the PIN using PBKDF2 with a fixed salt.
    Matches instructions: CryptoJS.PBKDF2(PIN, SALT_FIXO, { keySize: 256/32 })
    """
    # Using SHA256 as it is standard and secure.
    # Must ensure JS side uses SHA256 as well.
    return hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), SALT_FIXO, ITERATIONS, dklen=KEY_SIZE)

def encrypt_payload(payload: dict, pin: str) -> str:
    try:
        json_str = json.dumps(payload)
        data_bytes = json_str.encode('utf-8')

        key = get_key(pin)
        iv = get_random_bytes(16)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))

        # Token structure: JSON -> Base64
        token_data = {
            "iv": base64.b64encode(iv).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

        json_token = json.dumps(token_data)
        # URL-safe Base64 encoding
        return base64.urlsafe_b64encode(json_token.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return ""

def decrypt_payload(token: str, pin: str) -> dict:
    try:
        # Decode URL-safe Base64
        # Add padding if missing (urlsafe_b64decode requires correct padding sometimes, strictly)
        # But usually urlsafe_b64decode handles it if we are consistent.
        # Let's verify padding handling.
        missing_padding = len(token) % 4
        if missing_padding:
            token += '=' * (4 - missing_padding)

        json_token_bytes = base64.urlsafe_b64decode(token)
        json_token = json_token_bytes.decode('utf-8')
        token_data = json.loads(json_token)

        iv = base64.b64decode(token_data["iv"])
        ciphertext = base64.b64decode(token_data["ciphertext"])

        key = get_key(pin)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_data = unpad(decrypted_padded, AES.block_size)

        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# Test
def run_test():
    pin = "123456"
    payload = {
        "ownerName": "Jules",
        "receiverName": "User",
        "drawId": "test_id",
        "revealAt": None,
        "salt": "random_salt"
    }

    print(f"Original Payload: {payload}")
    print(f"PIN: {pin}")

    token = encrypt_payload(payload, pin)
    print(f"Encrypted Token: {token}")

    # Simulate URL encoding/decoding just in case
    url_encoded_token = urllib.parse.quote(token)
    print(f"URL Encoded Token: {url_encoded_token}")

    url_decoded_token = urllib.parse.unquote(url_encoded_token)

    decrypted = decrypt_payload(url_decoded_token, pin)
    print(f"Decrypted Payload: {decrypted}")

    assert decrypted == payload
    print("Test Passed!")

if __name__ == "__main__":
    run_test()
