import os
import base64
import json
import random
import string
from datetime import datetime
from functools import wraps
from flask import Flask, request, abort, render_template, redirect, url_for, session, jsonify, Response

from firebase_config import FirebaseDB
from crypto_manager import CryptoManager
from translations import LANGUAGES, get_text

app = Flask(__name__)
app.secret_key = os.urandom(24)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "Keys", "PrivateKey.prk")

if os.path.exists(PRIVATE_KEY_PATH):
    crypto = CryptoManager(PRIVATE_KEY_PATH)
else:
    crypto = None
    print(f"CRITICAL: Private key not found at {PRIVATE_KEY_PATH}")

def token_response(data):
    if not crypto: return "Error"
    json_data = json.dumps(data)
    data_hash = crypto.sha256(json_data)
    ack_token = {
        "Data": crypto.profile_encrypt(json_data, data_hash),
        "Sign": crypto.sign_by_private(json_data),
        "Hash": data_hash
    }
    return base64.b64encode(json.dumps(ack_token).encode()).decode()

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "Sizan")

def get_admin_password():
    creds = FirebaseDB.get_admin_creds()
    env_password = os.environ.get("ADMIN_PASSWORD")
    if env_password:
        return env_password
    if creds:
        return creds.get("password", "Sizan")
    FirebaseDB.set_admin_creds({"username": ADMIN_USERNAME, "password": "Sizan"})
    return "Sizan"

ADMIN_PASSWORD = get_admin_password()

def generate_license_key():
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f"SIZAN-{random_part}"

def get_lang():
    return session.get('lang', 'en')

def t(key, **kwargs):
    return get_text(key, get_lang(), **kwargs)

@app.context_processor
def inject_globals():
    return dict(t=t, lang=get_lang(), LANGUAGES=LANGUAGES)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def reseller_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'reseller_logged_in' not in session:
            return redirect(url_for('reseller_login'))
        return f(*args, **kwargs)
    return decorated_function

# ── Language Switch ──

@app.route('/lang/<lang_code>')
def set_lang(lang_code):
    if lang_code in LANGUAGES:
        session['lang'] = lang_code
    referrer = request.referrer or url_for('home')
    return redirect(referrer)

# ── Admin Panel Routes ──

@app.route('/')
def home():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    if 'reseller_logged_in' in session:
        return redirect(url_for('reseller_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            session['panel_type'] = 'admin'
            return redirect(url_for('dashboard'))
        else:
            error = t('invalid_credentials')
    return render_template('login.html', error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    server = FirebaseDB.get_server_status()
    user = session.get('user')
    if not user:
        users = FirebaseDB.list_users()
        if users:
            uid = list(users.keys())[0]
            user = users[uid]
            user['firebase_id'] = uid
        else:
            user = {
                "usuario": "Admin_Sizan",
                "tipo": "1",
                "expiracao": "2030-12-20 23:59:59",
                "status": "1",
                "UID": "000000000000000",
                "version": "v1"
            }
    return render_template('dashboard.html', user=user, server=server, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/server_toggle', methods=['POST'])
@login_required
def server_toggle():
    new_status = request.form.get('status', 'ON')
    FirebaseDB.set_server_status({
        "status": new_status,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    return redirect(url_for('dashboard'))

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        days = int(request.form.get('days', 30))
        version = request.form.get('version', 'v1')
        user_type = request.form.get('type', '3')
        custom_expire = request.form.get('custom_expire')

        license_key = generate_license_key()
        while FirebaseDB.get_user_by_username(license_key):
            license_key = generate_license_key()

        if custom_expire:
            dt = datetime.strptime(custom_expire, "%Y-%m-%dT%H:%M")
            expiracao_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        else:
            from datetime import timedelta
            dt_expire = datetime.now() + timedelta(days=days)
            expiracao_str = dt_expire.strftime("%Y-%m-%d %H:%M:%S")

        new_user = {
            "usuario": license_key,
            "senha": license_key,
            "expiracao": expiracao_str,
            "status": "1",
            "tipo": user_type,
            "UID": "000000000000000",
            "version": version,
            "CID": "1"
        }

        FirebaseDB.create_user(new_user)
        return redirect(url_for('users_list'))

    return render_template('add_user.html')

@app.route('/users_list')
@login_required
def users_list():
    users = FirebaseDB.list_users()
    search = request.args.get('q', '').strip().lower()
    if search and users:
        filtered = {}
        for fid, u in users.items():
            if (search in u.get('usuario', '').lower() or
                search in u.get('expiracao', '').lower() or
                search in u.get('UID', '').lower()):
                filtered[fid] = u
        users = filtered
    return render_template('users_list.html', users=users, search_q=search)

@app.route('/reset_device/<fid>')
@login_required
def reset_device(fid):
    FirebaseDB.update_user(fid, {"UID": "000000000000000"})
    return redirect(url_for('users_list'))

@app.route('/delete_user/<fid>')
@login_required
def delete_user(fid):
    FirebaseDB.delete_user(fid)
    return redirect(url_for('users_list'))

# ── Login History Routes ──

@app.route('/login_history/<fid>')
@login_required
def login_history(fid):
    user = FirebaseDB.get_user_by_fid(fid)
    history = FirebaseDB.get_login_history(fid)
    search = request.args.get('q', '').strip().lower()
    if search and history:
        filtered = {}
        for hid, entry in history.items():
            if (search in entry.get('uid', '').lower() or
                search in entry.get('ip', '').lower() or
                search in entry.get('time', '').lower()):
                filtered[hid] = entry
        history = filtered
    return render_template('login_history.html', user=user, history=history, fid=fid, search_q=search)

@app.route('/clear_history/<fid>')
@login_required
def clear_history(fid):
    FirebaseDB.clear_login_history(fid)
    return redirect(url_for('login_history', fid=fid))

@app.route('/delete_history/<fid>/<hid>')
@login_required
def delete_history(fid, hid):
    FirebaseDB.delete_history_entry(fid, hid)
    return redirect(url_for('login_history', fid=fid))

# ── Device Log Route ──

@app.route('/device_log')
@login_required
def device_log():
    users = FirebaseDB.list_users()
    all_entries = []
    if users:
        for fid, user in users.items():
            history = FirebaseDB.get_login_history(fid)
            if history:
                for hid, entry in history.items():
                    all_entries.append({
                        "fid": fid,
                        "hid": hid,
                        "key": user.get("usuario", "N/A"),
                        "uid": entry.get("uid", ""),
                        "ip": entry.get("ip", ""),
                        "time": entry.get("time", "")
                    })
    all_entries.sort(key=lambda x: x.get("time", ""), reverse=True)
    search = request.args.get('q', '').strip().lower()
    if search:
        filtered = []
        for e in all_entries:
            if (search in e['key'].lower() or search in e['uid'].lower() or
                search in e['ip'].lower() or search in e['time'].lower()):
                filtered.append(e)
        all_entries = filtered
    return render_template('device_log.html', entries=all_entries, search_q=search)

@app.route('/clear_all_device_logs')
@login_required
def clear_all_device_logs():
    users = FirebaseDB.list_users()
    if users:
        for fid in users:
            FirebaseDB.clear_login_history(fid)
    return redirect(url_for('device_log'))

# ── Reseller Management Routes ──

@app.route('/add_reseller', methods=['GET', 'POST'])
@login_required
def add_reseller():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template('add_reseller.html', error=t('invalid_credentials'))
        if FirebaseDB.get_reseller_by_username(username):
            return render_template('add_reseller.html', error=t('reseller_exists'))
        new_reseller = {
            "username": username,
            "password": password,
            "status": "1",
            "created_by": "Sizan",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        FirebaseDB.create_reseller(new_reseller)
        return redirect(url_for('resellers_list'))
    return render_template('add_reseller.html')

@app.route('/resellers_list')
@login_required
def resellers_list():
    resellers = FirebaseDB.list_resellers()
    search = request.args.get('q', '').strip().lower()
    if search and resellers:
        filtered = {}
        for rid, r in resellers.items():
            if (search in r.get('username', '').lower() or
                search in r.get('created_by', '').lower() or
                search in r.get('created_at', '').lower()):
                filtered[rid] = r
        resellers = filtered
    return render_template('resellers_list.html', resellers=resellers, search_q=search)

@app.route('/delete_reseller/<rid>')
@login_required
def delete_reseller(rid):
    FirebaseDB.delete_reseller(rid)
    return redirect(url_for('resellers_list'))

# ── Reseller Panel Routes ──

@app.route('/reseller/login', methods=['GET', 'POST'])
def reseller_login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        reseller = FirebaseDB.get_reseller_by_username(username)
        if reseller and reseller.get('password') == password and reseller.get('status') == "1":
            session['reseller_logged_in'] = True
            session['reseller_username'] = username
            session['panel_type'] = 'reseller'
            return redirect(url_for('reseller_dashboard'))
        else:
            error = t('invalid_reseller_creds')
    return render_template('reseller_login.html', error=error)

@app.route('/reseller/dashboard')
@reseller_login_required
def reseller_dashboard():
    server = FirebaseDB.get_server_status()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    users = FirebaseDB.list_users()
    search = request.args.get('q', '').strip().lower()
    if search and users:
        filtered = {}
        for fid, u in users.items():
            if (search in u.get('usuario', '').lower() or
                search in u.get('expiracao', '').lower()):
                filtered[fid] = u
        users = filtered
    return render_template('reseller_dashboard.html', server=server, now=now, users=users, search_q=search)

@app.route('/reseller/logout')
def reseller_logout():
    session.pop('reseller_logged_in', None)
    session.pop('reseller_username', None)
    session.pop('panel_type', None)
    return redirect(url_for('reseller_login'))

# ── Change Password ──

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    error = None
    success = None
    if request.method == 'POST':
        current = request.form.get('current_password')
        new_pass = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        global ADMIN_PASSWORD
        if current != ADMIN_PASSWORD:
            error = "Current password is incorrect."
        elif len(new_pass) < 4:
            error = "New password must be at least 4 characters."
        elif new_pass != confirm:
            error = "New passwords do not match."
        else:
            ADMIN_PASSWORD = new_pass
            FirebaseDB.set_admin_creds({"username": "Sizan", "password": ADMIN_PASSWORD})
            success = "Password changed successfully!"
    return render_template('change_password.html', error=error, success=success)

# ── Shared Logout ──

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('panel_type', None)
    return redirect(url_for('login'))

# ── API Routes ──

@app.route('/api/server_status')
def api_server_status():
    server = FirebaseDB.get_server_status()
    return {"status": server.get("status", "ON"), "updated_at": server.get("updated_at", "")}

# ── Android Client Auth Endpoint ──

@app.route('/api/client/auth', methods=['POST'])
def api_client_auth():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "invalid_request"}), 400

    key = data.get('key')
    hwid = data.get('hwid')
    version = data.get('version', 'v1')

    if not key or not hwid:
        return jsonify({"success": False, "message": "invalid_key"}), 400

    user = FirebaseDB.get_user_by_username(key)
    if not user or user.get('senha') != key:
        return jsonify({"success": False, "message": "invalid_key"}), 401

    if user.get('status') == "0":
        return jsonify({"success": False, "message": "key_banned"}), 403

    server = FirebaseDB.get_server_status()
    if server.get("status") == "OFF":
        return jsonify({"success": False, "message": "server_off"}), 503

    dt_now = datetime.now()
    try:
        dt_expire = datetime.strptime(user.get('expiracao'), "%Y-%m-%d %H:%M:%S")
    except:
        return jsonify({"success": False, "message": "key_expired"}), 403

    if dt_now >= dt_expire:
        return jsonify({"success": False, "message": "key_expired"}), 403

    stored_uid = user.get('UID')
    if stored_uid == "000000000000000":
        FirebaseDB.update_user(user['firebase_id'], {"UID": hwid})
        stored_uid = hwid

    if stored_uid != hwid:
        return jsonify({"success": False, "message": "device_limit_reached"}), 403

    FirebaseDB.add_login_history(user['firebase_id'], {
        "uid": hwid,
        "ip": request.remote_addr,
        "time": dt_now.strftime("%Y-%m-%d %H:%M:%S")
    })

    base_url = request.host_url.rstrip('/')
    file_url = f"{base_url}/api/client/download"

    return jsonify({
        "success": True,
        "session_token": hwid,
        "file_url": file_url,
        "seller": "Sizan",
        "version": "2.0"
    })

# ── Binary Download Endpoint ──

@app.route('/api/client/download')
def api_client_download():
    version = request.args.get('v', 'V3')
    loader_path = os.path.join(BASE_DIR, "loader", version, "PUBG.kmods")
    if not os.path.exists(loader_path):
        return "File not found", 404
    with open(loader_path, "rb") as f:
        data = f.read()
    return Response(data, mimetype='application/octet-stream', headers={
        'Content-Disposition': 'attachment; filename=PUBG.kmods'
    })

# ── Client Features Endpoint ──

@app.route('/api/client_features.php', methods=['GET'])
@app.route('/api/client_features', methods=['GET'])
def api_client_features():
    return jsonify({
        "success": True,
        "features": {
            "AIMBOT": [
                {"type": "toggle", "name": "Aimbot", "tid": 3},
                {"type": "toggle", "name": "Aim On Fire", "tid": 4},
                {"type": "toggle", "name": "Head Lock", "tid": 13},
                {"type": "slider", "name": "FOV", "tid": 14, "default": 360, "min": 0, "max": 360, "unit": "°"},
                {"type": "slider", "name": "Distance", "tid": 15, "default": 500, "min": 0, "max": 1000, "unit": "m"}
            ],
            "ESP": [
                {"type": "toggle", "name": "Enable ESP", "tid": 2},
                {"type": "toggle", "name": "Player Box", "tid": 5},
                {"type": "toggle", "name": "Health Bar", "tid": 6},
                {"type": "toggle", "name": "Snap Line", "tid": 8},
                {"type": "toggle", "name": "Name", "tid": 9},
                {"type": "toggle", "name": "Distance", "tid": 7},
                {"type": "toggle", "name": "Tracker", "tid": 11},
                {"type": "slider", "name": "ESP Color", "tid": 10, "default": 0, "min": 0, "max": 9}
            ],
            "MISC": [
                {"type": "toggle", "name": "Speed Hack", "tid": 16},
                {"type": "toggle", "name": "HUD Info", "tid": 12}
            ]
        }
    })

# ── Client Sellers Endpoint ──

@app.route('/api/client/sellers', methods=['GET'])
def api_client_sellers():
    return jsonify({
        "success": True,
        "contacts": [
            {"name": "Sizan", "telegram": "https://t.me/unknown_sizan"}
        ]
    })

# ── Old /api/login (keep for backward compatibility) ──

@app.route('/api/login', methods=['GET', 'POST'])
def api_login():
    if not crypto:
        return "Internal Server Error: Crypto not initialized", 500

    if request.method == 'GET':
        username = request.args.get('user')
        password = request.args.get('pass')
        device_uid = request.args.get('uid')

        if not username or not password:
            return jsonify({"success": False, "message": "Invalid parameters!"}), 400

        user = FirebaseDB.get_user_by_username(username)
        if not user or user.get('senha') != password:
            return jsonify({"success": False, "message": "Invalid login!"}), 401

        if user.get('status') == "0":
            return jsonify({"success": False, "message": "Banned!"}), 403

        server = FirebaseDB.get_server_status()
        if server.get("status") == "OFF":
            return jsonify({"success": False, "message": "Server is currently OFF. Please try again later."}), 503

        dt_now = datetime.now()
        try:
            dt_expire = datetime.strptime(user.get('expiracao'), "%Y-%m-%d %H:%M:%S")
        except:
            dt_expire = dt_now

        if dt_now >= dt_expire:
            return jsonify({"success": False, "message": "License expired!"}), 403

        stored_uid = user.get('UID')
        if stored_uid == "000000000000000":
            FirebaseDB.update_user(user['firebase_id'], {"UID": device_uid})
            stored_uid = device_uid

        if stored_uid != device_uid:
            return jsonify({"success": False, "message": "Device denied!"}), 403

        FirebaseDB.add_login_history(user['firebase_id'], {
            "uid": device_uid,
            "ip": request.remote_addr,
            "time": dt_now.strftime("%Y-%m-%d %H:%M:%S")
        })

        return jsonify({"success": True, "session_token": device_uid})

    token_post = request.form.get('token')
    if not token_post:
        return token_response({"Status": "Failed", "MessageString": "Error verifying login!"})

    try:
        token_bytes = base64.b64decode(token_post)
        tokarr = json.loads(token_bytes.decode('utf-8'))
        enc_data = tokarr.get('Data')
        dec_data_str = crypto.decrypt_by_private(enc_data)
        if not dec_data_str: raise ValueError("RSA Decryption failed")
        request_data = json.loads(dec_data_str)
    except Exception as e:
        return token_response({"Status": "Failed", "MessageString": f"Error: {str(e)}"})

    username = request_data.get('app_Us')
    password = request_data.get('app_Pa')
    device_uid = request_data.get('app_ID')
    login_ref = request.args.get('gdfasdgertdfswsdf', '')

    user = FirebaseDB.get_user_by_username(username)
    if not user or user.get('senha') != password:
        return token_response({"Status": "Failed", "MessageString": "Invalid login!"})

    if user.get('status') == "0":
        return token_response({"Status": "Failed", "MessageString": "Banned!"})

    server = FirebaseDB.get_server_status()
    if server.get("status") == "OFF":
        return token_response({"Status": "Failed", "MessageString": "Server is currently OFF. Please try again later."})

    dt_now = datetime.now()
    try:
        dt_expire = datetime.strptime(user.get('expiracao'), "%Y-%m-%d %H:%M:%S")
    except:
        dt_expire = dt_now

    if dt_now >= dt_expire:
        return token_response({"Status": "Failed", "MessageString": "License expired!"})

    stored_uid = user.get('UID')
    if stored_uid == "000000000000000":
        FirebaseDB.update_user(user['firebase_id'], {"UID": device_uid})
        stored_uid = device_uid

    if stored_uid != device_uid:
        return token_response({"Status": "Failed", "MessageString": "Device denied!"})

    FirebaseDB.add_login_history(user['firebase_id'], {
        "uid": device_uid,
        "ip": request.remote_addr,
        "time": dt_now.strftime("%Y-%m-%d %H:%M:%S")
    })

    version_id = "V4" if login_ref == "x32v4" else "V3"
    loader_path = os.path.join(BASE_DIR, "loader", version_id, "PUBG.kmods")
    loader_b64 = ""
    if os.path.exists(loader_path):
        with open(loader_path, "rb") as f: loader_b64 = base64.b64encode(f.read()).decode()

    return token_response({
        "Status": "Success",
        "Loader": loader_b64,
        "MessageString": f"{{'Client':{username},'Days':{max(0, (dt_expire-dt_now).days)},'Game':{user.get('version', 'v1')}}}",
        "CurrUser": username, "CurrPass": password, "SubscriptionLeft": "1"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
