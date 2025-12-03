import json
import base64
import hashlib
import unittest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Configuration from prompt
SALT_FIXO = b"AMIGO_SECRETO_SALT_2025"
ITERATIONS = 10000
KEY_SIZE = 32 # 256 bits

def get_key(pin: str) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), SALT_FIXO, ITERATIONS, dklen=KEY_SIZE)

def encrypt_string(plaintext: str, pin: str) -> str:
    try:
        data_bytes = plaintext.encode('utf-8')
        key = get_key(pin)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
        token_data = {
            "iv": base64.b64encode(iv).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        json_token = json.dumps(token_data)
        return base64.urlsafe_b64encode(json_token.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return ""

def decrypt_string(token: str, pin: str) -> str:
    try:
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
        return unpad(decrypted_padded, AES.block_size).decode('utf-8')
    except Exception as e:
        return None

class TestCrypto(unittest.TestCase):
    def test_encrypt_decrypt(self):
        target = "Maria Silva"
        pin = "123456"
        token = encrypt_string(target, pin)
        self.assertIsNotNone(token)

        decrypted = decrypt_string(token, pin)
        self.assertEqual(decrypted, target)

    def test_reencrypt_flow(self):
        target = "Pedro Santos"
        pin_initial = "111111"
        pin_final = "999999"

        # Step 1: Encrypt with initial
        token_initial = encrypt_string(target, pin_initial)

        # Step 2: Decrypt with initial (Simulating transition)
        decrypted_temp = decrypt_string(token_initial, pin_initial)
        self.assertEqual(decrypted_temp, target)

        # Step 3: Encrypt with final
        token_final = encrypt_string(decrypted_temp, pin_final)

        # Step 4: Validate
        decrypted_final = decrypt_string(token_final, pin_final)
        self.assertEqual(decrypted_final, target)

        # Step 5: Ensure old pin fails
        fail_check = decrypt_string(token_final, pin_initial)
        self.assertIsNone(fail_check)

    def test_admin_recovery_flow(self):
        target = "Hidden Target"
        admin_pin = "654321"
        user_pin_old = "123456" # User PIN (lost)

        # 1. During creation, system creates a recovery blob with Admin PIN
        recovery_blob = encrypt_string(target, admin_pin)

        # 2. User loses PIN, Admin steps in
        # Admin decrypts recovery blob
        recovered_plaintext = decrypt_string(recovery_blob, admin_pin)
        self.assertEqual(recovered_plaintext, target)

        # 3. Admin generates NEW initial PIN
        new_initial_pin = "999999"

        # 4. Admin re-encrypts target for user
        new_enc_target = encrypt_string(recovered_plaintext, new_initial_pin)

        # 5. User can now access with new initial PIN
        user_access = decrypt_string(new_enc_target, new_initial_pin)
        self.assertEqual(user_access, target)

if __name__ == "__main__":
    unittest.main()
