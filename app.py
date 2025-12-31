"""
Expert Full-Stack Software Architecture: Main Entry Point.
Implements Flask app with background workers for Syslog and Firewall Sync.
Fixes: Missing service-group/apps in sync payload & Application Context.
"""

import os
import threading
import socket
import logging
import time
from datetime import datetime
from typing import List

from flask import Flask, redirect, url_for, session, request
from sqlalchemy import event
from sqlalchemy.engine import Engine

# ייבוא מודולים פנימיים
from config import Config
from managers.models import db_sql, TrafficLog
from managers.fw_manager import load_app_ids, get_fw_connection
from managers.sync_manager import SyncManager

# Blueprints
from routes.auth_routes import auth_bp
from routes.main_routes import main_bp
from routes.rule_routes import rules_bp
from routes.object_routes import objects_bp
from routes.ops_routes import ops_bp

# הגדרות לוגים
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
werkzeug_log = logging.getLogger('werkzeug')
werkzeug_log.setLevel(logging.ERROR)

app = Flask(__name__)
app.config.from_object(Config)

# --------------------------------------------------------------------------
# 1. אופטימיזציה ל-SQLite
# --------------------------------------------------------------------------

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """מגדיר WAL Mode לשיפור ביצועי כתיבה במקביל."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
    except Exception as e:
        logger.warning(f"Could not set SQLite PRAGMAs: {e}")
    finally:
        cursor.close()

# --------------------------------------------------------------------------
# 2. תשתית מסד הנתונים
# --------------------------------------------------------------------------
def initialize_infrastructure():
    """מאתחל נתיבים, יוצר טבלאות וטוען קונפיגורציה ראשונית."""
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if db_uri.startswith('sqlite:///'):
        db_path = db_uri.replace('sqlite:///', '')
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    db_sql.init_app(app)

    with app.app_context():
        db_sql.create_all()
        try:
            load_app_ids()
            Config.validate_config()
            logger.info("✅ Database & Infrastructure Ready.")
        except Exception as e:
            logger.error(f"❌ Initialization Warning: {e}")

initialize_infrastructure()

app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(rules_bp)
app.register_blueprint(objects_bp)
app.register_blueprint(ops_bp)

# --------------------------------------------------------------------------
# 3. מנגנון סנכרון אוטומטי (Background Sync) - מתוקן
# --------------------------------------------------------------------------
def auto_sync_worker(flask_app: Flask) -> None:
    """
    Thread לסנכרון מול ה-Firewall API.
    מתוקן: שולח את כל האובייקטים הנדרשים כדי למנוע הופעת ANY בחוקים.
    """
    from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup
    from panos.policies import SecurityRule, Rulebase

    logger.info("🚀 Background Sync Worker initialized.")

    while True:
        with flask_app.app_context():
            try:
                start_time = datetime.now()
                fw = get_fw_connection()
                rb = Rulebase()
                fw.add(rb)

                # שליפת נתונים גולמיים
                addr_objs = AddressObject.refreshall(fw)
                addr_groups = AddressGroup.refreshall(fw)
                svc_objs = ServiceObject.refreshall(fw)
                svc_groups = ServiceGroup.refreshall(fw)
                rules_objs = SecurityRule.refreshall(rb)

                # חילוץ אפליקציות מהחוקים (מכיוון שאין App.refreshall פשוט)
                found_apps = set()
                for r in rules_objs:
                    apps = r.application
                    if isinstance(apps, list): found_apps.update(apps)
                    elif apps: found_apps.add(apps)
                
                apps_payload = [{"name": app, "description": "System", "is_group": False} 
                               for app in found_apps if app and app.lower() != 'any']

                fw_config = {
                    'address': [obj.about() for obj in addr_objs],
                    'address-group': [obj.about() for obj in addr_groups],
                    'service': [obj.about() for obj in svc_objs],
                    'service-group': [obj.about() for obj in svc_groups],
                    'rules': [obj.about() for obj in rules_objs],
                    'applications': apps_payload
                }

                sync_mgr = SyncManager(fw)
                if sync_mgr.sync_all(fw_config):
                    duration = (datetime.now() - start_time).total_seconds()
                    logger.info(f"✅ Auto-Sync success ({duration:.2f}s). Rules: {len(rules_objs)}")
                else:
                    logger.warning("⏳ Sync skipped (Lock active).")

            except Exception as e:
                logger.error(f"❌ Sync Worker Error: {str(e)}")

        time.sleep(300)

# --------------------------------------------------------------------------
# 4. ניהול לוגים (Syslog & Retention)
# --------------------------------------------------------------------------
def syslog_listener(flask_app: Flask) -> None:
    """מאזין ללוגים ב-UDP ומבצע Batch Insert."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', Config.SYSLOG_PORT))
        logger.info(f"📡 Syslog Listener active on port {Config.SYSLOG_PORT}")
    except Exception as e:
        logger.error(f"❌ Syslog Bind Error: {e}")
        return

    log_batch: List[TrafficLog] = []
    last_flush = time.time()

    while True:
        try:
            sock.settimeout(2.0)
            try:
                data, _ = sock.recvfrom(4096)
                msg = data.decode('utf-8', errors='ignore')
                if 'TRAFFIC' in msg:
                    parts = msg.split(',')
                    if len(parts) > 30:
                        new_entry = TrafficLog(
                            time=datetime.now().strftime("%H:%M:%S"),
                            source=parts[7], destination=parts[8],
                            app=parts[14], dst_port=parts[25],
                            src_zone=parts[16], dst_zone=parts[17],
                            protocol=parts[29], action=parts[30]
                        )
                        log_batch.append(new_entry)
            except socket.timeout: pass

            if len(log_batch) >= 50 or (time.time() - last_flush > 10 and log_batch):
                with flask_app.app_context():
                    db_sql.session.bulk_save_objects(log_batch)
                    db_sql.session.commit()
                log_batch = []
                last_flush = time.time()
        except Exception as e:
            logger.error(f"❌ Syslog Error: {e}")

# --------------------------------------------------------------------------
# 5. הגנת גישה והרצה
# --------------------------------------------------------------------------
@app.before_request
def require_login():
    allowed = ['auth.login', 'static']
    if 'user' not in session and request.endpoint not in allowed:
        return redirect(url_for('auth.login'))

if __name__ == '__main__':
    threads = [
        threading.Thread(target=syslog_listener, args=(app,), name="SyslogThread", daemon=True),
        threading.Thread(target=auto_sync_worker, args=(app,), name="SyncThread", daemon=True)
    ]
    for t in threads: t.start()
    app.run(debug=True, host='0.0.0.0', port=5100, use_reloader=False)