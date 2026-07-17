import base64
import hashlib
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_PKCS1_v1_5
from Crypto.Hash import SHA256

class CryptoManager:
    """Manages RSA and XOR encryption logic ported from PHP Crypter and Utils."""
    
    def __init__(self, private_key_path):
        with open(private_key_path, 'r') as f:
            self.private_key = RSA.import_key(f.read())
            
    def decrypt_by_private(self, enc_data_b64):
        """Decrypts data encrypted with RSA Public Key."""
        try:
            ciphertext = base64.b64decode(enc_data_b64)
            cipher = PKCS1_v1_5.new(self.private_key)
            # Sentinel is required for PKCS1_v1_5 to prevent padding oracle attacks
            sentinel = b"DECRYPT_FAILURE"
            decrypted = cipher.decrypt(ciphertext, sentinel)
            if decrypted == sentinel:
                return None
            return decrypted.decode('utf-8').strip()
        except Exception as e:
            print(f"RSA Decryption error: {e}")
            return None

    def sign_by_private(self, data):
        """Signs data with RSA Private Key using SHA256."""
        try:
            h = SHA256.new(data.encode('utf-8'))
            signer = Signature_PKCS1_v1_5.new(self.private_key)
            signature = signer.sign(h)
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            print(f"RSA Signing error: {e}")
            return None

    @staticmethod
    def profile_encrypt(data, hash_str):
        """XOR implementation of PHP profileEncrypt."""
        out = []
        for i in range(len(data)):
            out.append(chr(ord(data[i]) ^ ord(hash_str[i % len(hash_str)])))
        xored = "".join(out)
        return base64.b64encode(xored.encode('latin-1')).decode('utf-8')

    @staticmethod
    def sha256(data):
        """Helper for SHA256 hash in uppercase (PHP compatible)."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest().upper()
