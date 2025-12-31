import os
import threading
import socket
import time
import random
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from flask import Flask, redirect, url_for, session, request, jsonify
from managers.models import db_sql, TrafficLog
from config import Config
from managers.fw_manager import load_app_ids, refresh_fw_cache, get_fw_connection
from managers.sync_manager import SyncManager
from managers.data_manager import db
from routes.auth_routes import auth_bp
from routes.main_routes import main_bp
from routes.rule_routes import rules_bp
from routes.object_routes import objects_bp
from routes.ops_routes import ops_bp # וודא ששם הקובץ/blueprint תואם

app = Flask(__name__)
app.config.from_object(Config)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR) # רק שגיאות יוצגו, לא בקשות GET/POST רגילות


# --------------------------------------------------------------------------
# 1. תשתית מסד הנתונים והגדרות סביבה
# --------------------------------------------------------------------------
def initialize_infrastructure():
    """מוודא קיום תיקיות בסיס נתונים ומאתחל טבלאות."""
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if db_uri.startswith('sqlite:///'):
        db_path = db_uri.replace('sqlite:///', '')
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    db_sql.init_app(app)

    with app.app_context():
        # יצירת טבלאות בשני בסיסי הנתונים (Main + Logs)
        db_sql.create_all()
        try:
            load_app_ids()  # טעינת תשתיות App-ID בסיסיות
        except Exception as e:
            print(f"[!] App-ID Load Warning: {e}")

initialize_infrastructure()

# רישום Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(rules_bp)
app.register_blueprint(objects_bp)
app.register_blueprint(ops_bp)

# --------------------------------------------------------------------------
# 2. מנגנון סנכרון אוטומטי (Background Sync Manager)
# --------------------------------------------------------------------------
def auto_sync_worker(flask_app: Flask) -> None:
    """
    Thread שרץ ברקע ומעדכן את ה-DB המקומי מהפיירוול כל 5 דקות.
    מבוצע בתוך Flask App Context כדי לאפשר גישה ל-DB.
    """
    # ייבוא בתוך הפונקציה למניעת Circular Import
    from panos.objects import AddressObject, AddressGroup, ServiceObject
    from panos.policies import SecurityRule, Rulebase

    with flask_app.app_context():
        while True:
            try:
                print(f"🔄 [{datetime.now().strftime('%H:%M:%S')}] Background Sync Started...")
                fw = get_fw_connection()
                
                rb = Rulebase()
                fw.add(rb)
                
                # שליפת הקונפיגורציה העדכנית ביותר
                fw_config = {
                    'address': [obj.about() for obj in AddressObject.refreshall(fw)],
                    'address-group': [obj.about() for obj in AddressGroup.refreshall(fw)],
                    'service': [obj.about() for obj in ServiceObject.refreshall(fw)],
                    'rules': [obj.about() for obj in SecurityRule.refreshall(rb)]
                }
                
                sync_mgr = SyncManager(fw)
                success = sync_mgr.sync_all(fw_config)
                
                if success:
                    print(f"✅ [{datetime.now().strftime('%H:%M:%S')}] Background Sync Completed.")
                else:
                    print(f"⏳ [{datetime.now().strftime('%H:%M:%S')}] Sync skipped (In-Progress).")
                    
            except Exception as e:
                print(f"❌ Background Sync Error: {str(e)}")
            
            time.sleep(300)

# --------------------------------------------------------------------------
# 3. הגנת גישה (Middleware)
# --------------------------------------------------------------------------
@app.before_request
def require_login():
    """מוודא אימות משתמש לכל נתיב למעט דף התחברות וסטטיקה."""
    allowed = ['auth.login', 'static']
    if 'user' not in session and request.endpoint not in allowed:
        return redirect(url_for('auth.login'))

# --------------------------------------------------------------------------
# 4. ניהול לוגי תעבורה (Syslog UDP Listener & Retention)
# --------------------------------------------------------------------------
def enforce_log_retention(flask_app: Flask) -> None:
    """
    מוודא שקובץ ה-DB של הלוגים אינו חורג מהנפח שהוגדר ב-Config.
    מבוצע באמצעות מחיקת רשומות ישנות וביצוע VACUUM.
    """
    with flask_app.app_context():
        # חילוץ נתיב ה-DB מתוך ה-Binds
        logs_uri = flask_app.config['SQLALCHEMY_BINDS'].get('logs', '')
        db_path = logs_uri.replace('sqlite:///', '')
        
        if os.path.exists(db_path) and os.path.getsize(db_path) > (Config.LOGS_DB_MAX_MB * 1024 * 1024):
            print(f"[*] Logs DB Cleanup Triggered ({Config.LOGS_DB_MAX_MB}MB Limit)")
            
            # מציאת ה-ID המקסימלי ומחיקת כל מה שמעבר ל-50,000 שורות האחרונות
            latest_id = db_sql.session.query(db_sql.func.max(TrafficLog.id)).scalar()
            if latest_id:
                limit_id = latest_id - 50000
                db_sql.session.query(TrafficLog).filter(TrafficLog.id < limit_id).delete()
                db_sql.session.commit()
                
                # כיווץ פיזי של הקובץ בדיסק
                db_sql.session.execute(db_sql.text("VACUUM"))

def syslog_listener(flask_app: Flask) -> None:
    """
    מאזין ללוגי תעבורה בפורט UDP 514 ומזריק אותם ל-DB הייעודי.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', Config.SYSLOG_PORT))
        print(f"[*] Syslog DB Listener active on port {Config.SYSLOG_PORT}")
    except Exception as e:
        print(f"[!] Syslog Bind Error: {e}")
        return

    while True:
        try:
            data, _ = sock.recvfrom(4096)
            msg = data.decode('utf-8', errors='ignore')
            parts = msg.split(',')
            
            # זיהוי לוגי תעבורה של Palo Alto (TRAFFIC מופיע באינדקס 3 בדרך כלל)
            if len(parts) > 20 and 'TRAFFIC' in parts[0:5]:
                with flask_app.app_context():
                    new_entry = TrafficLog(
                        time=datetime.now().strftime("%H:%M:%S"),
                        source=parts[7],
                        destination=parts[8],
                        app=parts[14],
                        dst_port=parts[25],
                        src_zone=parts[16],
                        dst_zone=parts[17],
                        protocol=parts[29] if len(parts) > 29 else 'tcp',
                        action=parts[30] if len(parts) > 30 else 'allow'
                    )
                    db_sql.session.add(new_entry)
                    db_sql.session.commit()
                    
                    # בדיקת נפח סטטיסטית (פעם ב-500 הודעות בממוצע)
                    if random.random() < 0.002:
                        enforce_log_retention(flask_app)
                        
        except Exception as e:
            # במערכת Production רצוי לתעד שגיאות לוגר כאן
            continue

# --------------------------------------------------------------------------
# 5. הרצת האפליקציה (Execution Entry Point)
# --------------------------------------------------------------------------
if __name__ == '__main__':
    # הרצת מאזין הלוגים ב-Thread נפרד (העברת app כארגומנט לפתרון ה-TypeError)
    log_thread = threading.Thread(
        target=syslog_listener, 
        args=(app,), 
        daemon=True,
        name="Thread-Syslog"
    )
    log_thread.start()
    
    # הרצת מנהל הסנכרון האוטומטי ב-Thread נפרד
    sync_thread = threading.Thread(
        target=auto_sync_worker, 
        args=(app,), 
        daemon=True,
        name="Thread-Sync"
    )
    sync_thread.start()
    
    # הרצת שרת ה-Flask
    # use_reloader=False קריטי כדי שה-Threads לא יופעלו פעמיים ויגרמו לנעילת פורט 514
    app.run(debug=True, host='0.0.0.0', port=5100, use_reloader=False)