import requests
import json
import os

FIREBASE_CONFIG = {
  "apiKey": os.environ.get("FIREBASE_API_KEY"),
  "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN"),
  "databaseURL": os.environ.get("FIREBASE_DATABASE_URL"),
  "projectId": os.environ.get("FIREBASE_PROJECT_ID"),
  "storageBucket": os.environ.get("FIREBASE_STORAGE_BUCKET"),
  "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID"),
  "appId": os.environ.get("FIREBASE_APP_ID"),
  "measurementId": os.environ.get("FIREBASE_MEASUREMENT_ID")
}

DB_URL = FIREBASE_CONFIG["databaseURL"]

class FirebaseDB:

    # ── Users (Licenses) ──

    @staticmethod
    def get_user_by_username(username):
        response = requests.get(f"{DB_URL}/users.json")
        if response.status_code != 200 or not response.json():
            return None
        users = response.json()
        for uid, user_data in users.items():
            if user_data.get('usuario') == username:
                user_data['firebase_id'] = uid
                return user_data
        return None

    @staticmethod
    def get_user_by_fid(fid):
        response = requests.get(f"{DB_URL}/users/{fid}.json")
        if response.status_code != 200 or not response.json():
            return None
        user = response.json()
        user['firebase_id'] = fid
        return user

    @staticmethod
    def update_user(firebase_id, data):
        url = f"{DB_URL}/users/{firebase_id}.json"
        response = requests.patch(url, json=data)
        return response.status_code == 200

    @staticmethod
    def delete_user(firebase_id):
        url = f"{DB_URL}/users/{firebase_id}.json"
        response = requests.delete(url)
        return response.status_code == 200

    @staticmethod
    def create_user(data):
        url = f"{DB_URL}/users.json"
        response = requests.post(url, json=data)
        return response.status_code == 200

    @staticmethod
    def list_users():
        response = requests.get(f"{DB_URL}/users.json")
        return response.json() if response.status_code == 200 else {}

    # ── Login History ──

    @staticmethod
    def add_login_history(firebase_id, entry):
        url = f"{DB_URL}/users/{firebase_id}/history.json"
        response = requests.post(url, json=entry)
        return response.status_code == 200

    @staticmethod
    def get_login_history(firebase_id):
        url = f"{DB_URL}/users/{firebase_id}/history.json"
        response = requests.get(url)
        return response.json() if response.status_code == 200 else {}

    @staticmethod
    def clear_login_history(firebase_id):
        url = f"{DB_URL}/users/{firebase_id}/history.json"
        response = requests.delete(url)
        return response.status_code == 200

    @staticmethod
    def delete_history_entry(firebase_id, history_id):
        url = f"{DB_URL}/users/{firebase_id}/history/{history_id}.json"
        response = requests.delete(url)
        return response.status_code == 200

    # ── Resellers ──

    @staticmethod
    def get_reseller_by_username(username):
        response = requests.get(f"{DB_URL}/resellers.json")
        if response.status_code != 200 or not response.json():
            return None
        resellers = response.json()
        for rid, data in resellers.items():
            if data.get('username') == username:
                data['reseller_id'] = rid
                return data
        return None

    @staticmethod
    def list_resellers():
        response = requests.get(f"{DB_URL}/resellers.json")
        return response.json() if response.status_code == 200 else {}

    @staticmethod
    def create_reseller(data):
        url = f"{DB_URL}/resellers.json"
        response = requests.post(url, json=data)
        return response.status_code == 200

    @staticmethod
    def update_reseller(reseller_id, data):
        url = f"{DB_URL}/resellers/{reseller_id}.json"
        response = requests.patch(url, json=data)
        return response.status_code == 200

    @staticmethod
    def delete_reseller(reseller_id):
        url = f"{DB_URL}/resellers/{reseller_id}.json"
        response = requests.delete(url)
        return response.status_code == 200

    # ── Admin Credentials ──

    @staticmethod
    def get_admin_creds():
        url = f"{DB_URL}/admin/credentials.json"
        response = requests.get(url)
        if response.status_code == 200 and response.json():
            return response.json()
        return None

    @staticmethod
    def set_admin_creds(data):
        url = f"{DB_URL}/admin/credentials.json"
        response = requests.put(url, json=data)
        return response.status_code == 200

    # ── Server Status ──

    @staticmethod
    def get_server_status():
        url = f"{DB_URL}/server_status.json"
        response = requests.get(url)
        if response.status_code == 200 and response.json():
            return response.json()
        return {"status": "ON", "updated_at": ""}

    @staticmethod
    def set_server_status(data):
        url = f"{DB_URL}/server_status.json"
        response = requests.put(url, json=data)
        return response.status_code == 200
