import sys
import os
import json
import base64
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# Path setup
BASE_DIR = r"c:\Users\Administrator\Documents\Root_PANAL\flask_app"
PUB_KEY_PATH = os.path.join(BASE_DIR, "Keys", "PublicKey.puk")

def encrypt_rsa(data, key_path):
    with open(key_path, 'rb') as f:
        key = RSA.importKey(f.read())
    cipher = PKCS1_v1_5.new(key)
    # RSA PKCS1 v1.5 can only encrypt data up to (key_size_in_bytes - 11)
    # 1024 bit key = 128 bytes. 128 - 11 = 117 bytes max.
    # Our JSON is small enough.
    return base64.b64encode(cipher.encrypt(data.encode())).decode()

def generate_curl_token(username, password):
    # Data Payload
    req_data = {
        "app_Us": username,
        "app_Pa": password,
        "app_Version": "v1",
        "app_ID": "TEST-DEVICE-ID-123"
    }
    json_data = json.dumps(req_data)
    
    # Encrypt Data
    enc_data = encrypt_rsa(json_data, PUB_KEY_PATH)
    
    # Generate Hash
    data_hash = hashlib.sha256(json_data.encode()).hexdigest()
    
    # Final Token Structure
    full_token = {
        "Data": enc_data,
        "Hash": data_hash
    }
    
    # Final Base64
    final_b64 = base64.b64encode(json.dumps(full_token).encode()).decode()
    return final_b64

if __name__ == "__main__":
    user = sys.argv[1] if len(sys.argv) > 1 else "admin"
    pw = sys.argv[2] if len(sys.argv) > 2 else "admin"
    
    token = generate_curl_token(user, pw)
    ua = "BADOFTRUE/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T)/537.36 (KHTML, like Bad)"
    
    print(f'curl -X POST "https://sizan-panel-tau.vercel.app/api/login" \\')
    print(f'     -H "User-Agent: {ua}" \\')
    print(f'     -H "Content-Type: application/x-www-form-urlencoded" \\')
    print(f'     --data-urlencode "token={token}"')
