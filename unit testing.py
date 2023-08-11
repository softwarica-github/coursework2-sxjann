import unittest
import pickle
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Tuple

def aes_encryption(plain_text) -> Tuple:
    symmetric_key = get_random_bytes(16)
    cipher = AES.new(symmetric_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return pickle.dumps((ciphertext, nonce, tag, symmetric_key))

def aes_decryption(encrypted_data, symmetric_key):
    encrypted_ciphertext, nonce, tag, _ = pickle.loads(encrypted_data)

    cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)

    decrypted_data = cipher.decrypt_and_verify(encrypted_ciphertext, tag)
    return decrypted_data.decode('utf-8')

class TestAESEncryption(unittest.TestCase):

    def test_encryption_decryption(self):
        plain_text = "This is a test message"
        encrypted_data = aes_encryption(plain_text)
        
        _, _, _, symmetric_key = pickle.loads(encrypted_data)
    
        decrypted_data = aes_decryption(encrypted_data, symmetric_key)

        self.assertEqual(decrypted_data, plain_text)

if __name__ == '__main__':
    unittest.main()
