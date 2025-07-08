from flask import Flask, request, redirect, render_template, send_from_directory
import hashlib, json, os, time, qrcode
from datetime import datetime
import requests
from collections import defaultdict

app = Flask(__name__)

URL_FILE = 'urls.json'
ANALYTICS_FILE = 'analytics.json'
QR_DIR = 'static/qrcodes'
os.makedirs(QR_DIR, exist_ok=True)

# Load or initialize storage
url_map = json.load(open(URL_FILE)) if os.path.exists(URL_FILE) else {}
analytics = json.load(open(ANALYTICS_FILE)) if os.path.exists(ANALYTICS_FILE) else {}

BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def base62_encode(num):
    if num == 0:
        return BASE62[0]
    s = ""
    while num:
        s = BASE62[num % 62] + s
        num //= 62
    return s

def hash_url(long_url):
    salt = 0
    while True:
        raw = long_url + str(salt)
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        short = base62_encode(int(hashed, 16))[:6]
        if short not in url_map or url_map[short]['original_url'] == long_url:
            return short
        salt += 1

def get_expiration_seconds(option):
    mapping = {
        "5m": 5 * 60,
        "1h": 60 * 60,
        "1d": 24 * 60 * 60,
        "7d": 7 * 24 * 60 * 60,
        "never": None
    }
    return mapping.get(option, None)

def get_location(ip):
    try:
        res = requests.get(f"http://ipinfo.io/{ip}/json")
        data = res.json()
        return data.get("region", "Unknown"), data.get("country", "Unknown")
    except:
        return "Unknown", "Unknown"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/shorten', methods=['GET', 'POST'])
def shorten():
    if request.method == 'GET':
        return redirect('/')

    long_url = request.form['long_url']
    custom_alias = request.form.get('custom_alias', '').strip()
    password = request.form.get('password', '').strip()
    expire_option = request.form.get('expiration', 'never')
    created_at = time.time()
    expire_at = None if expire_option == 'never' else created_at + get_expiration_seconds(expire_option)

    if custom_alias:
        if custom_alias in url_map and url_map[custom_alias]['original_url'] != long_url:
            return "❌ Custom alias already in use!", 400
        short = custom_alias
    else:
        short = hash_url(long_url)

    url_map[short] = {
        "original_url": long_url,
        "created_at": created_at,
        "expire_at": expire_at,
        "clicks": 0,
        "password": password if password else None
    }

    json.dump(url_map, open(URL_FILE, 'w'))

    # Generate QR code
    short_url = request.host_url + short
    qr_img = qrcode.make(short_url)
    qr_path = os.path.join(QR_DIR, f"{short}.png")
    qr_img.save(qr_path)

    return render_template("index.html", short_url=short_url, qr_code_filename=f"qrcodes/{short}.png")

@app.route('/<short>', methods=['GET', 'POST'])
def redirect_to_original(short):
    entry = url_map.get(short)
    if not entry:
        return "❌ Short URL not found!", 404

    if entry['expire_at'] and time.time() > entry['expire_at']:
        return "⏰ Link Expired!", 410

    # Handle password protection
    if entry.get('password'):
        if request.method == 'GET':
            return render_template("password_prompt.html", short=short)
        user_pass = request.form.get('password', '')
        if user_pass != entry['password']:
            return render_template("password_prompt.html", short=short, error="❌ Incorrect password")

    # Count click
    entry['clicks'] += 1
    json.dump(url_map, open(URL_FILE, 'w'))

    # Location tracking
    ip = request.remote_addr
    region, country = get_location(ip)

    click_info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "region": region,
        "country": country,
        "user_agent": request.headers.get('User-Agent')
    }

    analytics.setdefault(short, []).append(click_info)
    json.dump(analytics, open(ANALYTICS_FILE, 'w'))

    return redirect(entry['original_url'])

@app.route('/history')
def history():
    return render_template("history.html", urls=url_map)

@app.route('/stats/<short>')
def stats(short):
    if short not in url_map:
        return "❌ Invalid URL code", 404
    clicks = analytics.get(short, [])
    return render_template("analytics.html", short=short, logs=clicks)

@app.route('/chart.js')
def serve_chart():
    return send_from_directory('.', 'chart.js')

@app.template_filter('datetimeformat')
def datetimeformat(value):
    if value is None:
        return "Never"
    return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')

if __name__ == '__main__':
    app.run(debug=True)
