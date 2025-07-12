import json
import os
from models import db, URL, User, Analytics
from werkzeug.security import generate_password_hash

def migrate_json_to_database():
    """Migrate existing JSON data to database"""
    
    # Migrate URLs
    if os.path.exists('urls.json'):
        with open('urls.json', 'r') as f:
            urls_data = json.load(f)
        
        for short_code, data in urls_data.items():
            # Check if URL already exists
            existing_url = URL.query.filter_by(short_code=short_code).first()
            if not existing_url:
                url = URL(
                    short_code=short_code,
                    original_url=data['original_url'],
                    created_at=data.get('created_at', 0),
                    expire_at=data.get('expire_at'),
                    clicks=data.get('clicks', 0),
                    password=data.get('password'),
                    user_id=data.get('user_id')
                )
                db.session.add(url)
        
        print(f"Migrated {len(urls_data)} URLs to database")
    
    # Migrate Users
    if os.path.exists('users.json'):
        with open('users.json', 'r') as f:
            users_data = json.load(f)
        
        for username, password_hash in users_data.items():
            # Check if user already exists
            existing_user = User.query.filter_by(username=username).first()
            if not existing_user:
                user = User(
                    username=username,
                    password_hash=password_hash
                )
                db.session.add(user)
        
        print(f"Migrated {len(users_data)} users to database")
    
    # Migrate Analytics
    if os.path.exists('analytics.json'):
        with open('analytics.json', 'r') as f:
            analytics_data = json.load(f)
        
        total_analytics = 0
        for short_code, logs in analytics_data.items():
            for log in logs:
                # Check if this exact analytics entry exists
                existing_analytics = Analytics.query.filter_by(
                    short_code=short_code,
                    timestamp=log.get('timestamp', ''),
                    ip=log.get('ip', '')
                ).first()
                
                if not existing_analytics:
                    analytics = Analytics(
                        short_code=short_code,
                        timestamp=log.get('timestamp', ''),
                        ip=log.get('ip', ''),
                        region=log.get('region', 'Unknown'),
                        country=log.get('country', 'Unknown'),
                        user_agent=log.get('user_agent', '')
                    )
                    db.session.add(analytics)
                    total_analytics += 1
        
        print(f"Migrated {total_analytics} analytics entries to database")
    
    # Commit all changes
    try:
        db.session.commit()
        print("Migration completed successfully!")
    except Exception as e:
        db.session.rollback()
        print(f"Migration failed: {e}")

def backup_json_files():
    """Create backup of existing JSON files"""
    import shutil
    from datetime import datetime
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"backup_{timestamp}"
    
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    files_to_backup = ['urls.json', 'users.json', 'analytics.json']
    
    for file in files_to_backup:
        if os.path.exists(file):
            shutil.copy2(file, os.path.join(backup_dir, file))
            print(f"Backed up {file} to {backup_dir}")
    
    return backup_dir