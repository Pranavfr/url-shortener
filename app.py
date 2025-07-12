from flask import Flask, request, redirect, render_template, send_from_directory, session, url_for
import hashlib, json, os, time, qrcode
from datetime import datetime
import requests
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Import database models
from models import db, URL, User as UserModel, Analytics
from database_utils import migrate_json_to_database, backup_json_files

app = Flask(__name__)
app.secret_key = 'your-very-secure-secret'  # Replace this for production

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///url_shortener.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

QR_DIR = 'static/qrcodes'
os.makedirs(QR_DIR, exist_ok=True)

ADMIN_IPS = ['127.0.0.1']  # Update with your real admin IP if hosted

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
        
        # Check if short code exists in database
        existing_url = URL.query.filter_by(short_code=short).first()
        if not existing_url or existing_url.original_url == long_url:
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

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def get_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        region = data.get("regionName", "Unknown")
        country = data.get("country", "Unknown")
        return region, country
    except Exception as e:
        print(f"[ERROR] Location fetch failed for IP {ip}: {e}")
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

    if current_user.is_authenticated:
        user_id = current_user.id
    else:
        user_id = session.get('user_id')
        if not user_id:
            user_id = str(time.time()) + get_client_ip()
            session['user_id'] = user_id

    if custom_alias:
        existing_url = URL.query.filter_by(short_code=custom_alias).first()
        if existing_url and existing_url.original_url != long_url:
            return "❌ Custom alias already in use!", 400
        short = custom_alias
    else:
        short = hash_url(long_url)

    # Check if URL already exists, if so update it
    existing_url = URL.query.filter_by(short_code=short).first()
    if existing_url:
        existing_url.original_url = long_url
        existing_url.created_at = created_at
        existing_url.expire_at = expire_at
        existing_url.password = password if password else None
        existing_url.user_id = user_id
    else:
        # Create new URL entry
        new_url = URL(
            short_code=short,
            original_url=long_url,
            created_at=created_at,
            expire_at=expire_at,
            clicks=0,
            password=password if password else None,
            user_id=user_id
        )
        db.session.add(new_url)

    db.session.commit()

    short_url = request.host_url + short
    qr_img = qrcode.make(short_url)
    qr_path = os.path.join(QR_DIR, f"{short}.png")
    qr_img.save(qr_path)

    return render_template("index.html", short_url=short_url, qr_code_filename=f"qrcodes/{short}.png")

@app.route('/<short>', methods=['GET', 'POST'])
def redirect_to_original(short):
    url_entry = URL.query.filter_by(short_code=short).first()
    if not url_entry:
        return "❌ Short URL not found!", 404

    if url_entry.expire_at and time.time() > url_entry.expire_at:
        return "⏰ Link Expired!", 410

    if url_entry.password:
        if request.method == 'GET':
            return render_template("password_prompt.html", short=short)
        user_pass = request.form.get('password', '')
        if user_pass != url_entry.password:
            return render_template("password_prompt.html", short=short, error="❌ Incorrect password")

    # Increment clicks
    url_entry.clicks += 1
    db.session.commit()

    # Log analytics
    ip = get_client_ip()
    region, country = get_location(ip)

    analytics = Analytics(
        short_code=short,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip=ip,
        region=region,
        country=country,
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(analytics)
    db.session.commit()

    return redirect(url_entry.original_url)

@app.route('/history')
@login_required
def history():
    user_urls = URL.query.filter_by(user_id=current_user.id).all()
    urls_dict = {url.short_code: url.to_dict() for url in user_urls}
    return render_template("history.html", urls=urls_dict)

@app.route('/stats/<short>')
def stats(short):
    url_entry = URL.query.filter_by(short_code=short).first()
    if not url_entry:
        return "❌ Invalid URL code", 404
    
    analytics_logs = Analytics.query.filter_by(short_code=short).all()
    logs = [log.to_dict() for log in analytics_logs]
    return render_template("analytics.html", short=short, logs=logs)

@app.route('/chart.js')
def serve_chart():
    return send_from_directory('.', 'chart.js')

@app.template_filter('datetimeformat')
def datetimeformat(value):
    if value is None:
        return "Never"
    return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

class User(UserMixin):
    def __init__(self, username):
        self.id = username

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    user = UserModel.query.filter_by(username=user_id).first()
    if user:
        return User(user_id)
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        existing_user = UserModel.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="Username already exists.")
        
        new_user = UserModel(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user = UserModel.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(User(username))
            return redirect('/dashboard')
        return render_template('login.html', error="Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/dashboard')
@login_required
def dashboard():
    user_urls = URL.query.filter_by(user_id=current_user.id).all()
    urls_dict = {url.short_code: url.to_dict() for url in user_urls}
    
    # Collect analytics data for chart
    analytics_data = {}
    for url in user_urls:
        analytics_logs = Analytics.query.filter_by(short_code=url.short_code).all()
        clicks = []
        for log in analytics_logs:
            try:
                # Parse timestamp and format as date
                log_date = datetime.strptime(log.timestamp, "%Y-%m-%d %H:%M:%S").strftime('%Y-%m-%d')
                clicks.append(log_date)
            except:
                # Fallback for different timestamp formats
                clicks.append(log.timestamp.split(' ')[0] if ' ' in log.timestamp else log.timestamp)
        analytics_data[url.short_code] = clicks
    
    return render_template("dashboard.html", urls=urls_dict, analytics=analytics_data)

@app.route('/analytics/<short>')
@login_required
def analytics_view(short):
    url_entry = URL.query.filter_by(short_code=short).first()
    if not url_entry:
        return "❌ Invalid URL code", 404
    
    analytics_logs = Analytics.query.filter_by(short_code=short).all()
    logs = [log.to_dict() for log in analytics_logs]
    return render_template("analytics.html", short=short, logs=logs)

@app.route('/analytics')
@login_required
def analytics_overview():
    user_urls = URL.query.filter_by(user_id=current_user.id).first()
    if user_urls:
        return redirect(url_for('analytics_view', short=user_urls.short_code))
    return "No links found!", 404

@app.route('/migrate')
def migrate_data():
    """Manual migration endpoint - remove this in production"""
    try:
        backup_dir = backup_json_files()
        migrate_json_to_database()
        return f"Migration completed! Backup created in {backup_dir}"
    except Exception as e:
        return f"Migration failed: {e}", 500

# Initialize database and migrate existing data
with app.app_context():
    db.create_all()
    
    # Check if we need to migrate existing JSON data
    if (os.path.exists('urls.json') or os.path.exists('users.json') or os.path.exists('analytics.json')):
        print("Found existing JSON files. Starting migration...")
        try:
            backup_dir = backup_json_files()
            migrate_json_to_database()
            print(f"Migration completed! Backup created in {backup_dir}")
        except Exception as e:
            print(f"Migration failed: {e}")

if __name__ == '__main__':
    app.run(debug=True)