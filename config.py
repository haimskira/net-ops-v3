import os
from dotenv import load_dotenv

# טעינת המשתנים מקובץ ה-env
load_dotenv()

IS_DOCKER = os.path.exists('/.dockerenv')

class Config:
    # Flask
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'default_secret_key_123')
    
    # Firewall (מושך מ-PA_API_KEY שב-env)
    FW_IP = os.getenv('FW_IP')
    API_KEY = os.getenv('PA_API_KEY') 
    
    LOCAL_ADMIN_USER = os.environ.get('LOCAL_ADMIN_USER', 'admin')
    LOCAL_ADMIN_PASS = os.environ.get('LOCAL_ADMIN_PASS')
    
    # Logging & Retention
    SYSLOG_PORT = int(os.getenv('SYSLOG_PORT', 514))
    LOGS_DB_MAX_MB = 100  # מגבלה של 100MB לבסיס הנתונים של הלוגים
    
    # LDAP
    LDAP_SERVER = os.getenv('LDAP_SERVER')
    LDAP_DOMAIN = os.getenv('LDAP_DOMAIN')
    LDAP_BASE_DN = os.getenv('LDAP_BASE_DN')
    LDAP_ADMIN_GROUP = os.getenv('LDAP_ADMIN_GROUP')
    LDAP_USER_GROUP = os.getenv('LDAP_USER_GROUP')
    
    # Database Configuration (Multi-DB Binding)
    if IS_DOCKER:
        db_path = '/app/data/netops.db'
        logs_db_path = '/app/data/traffic_logs.db'
    else:
        basedir = os.path.abspath(os.path.dirname(__file__))
        db_path = os.path.join(basedir, 'netops.db')
        logs_db_path = os.path.join(basedir, 'traffic_logs.db')
        
    # בסיס הנתונים הראשי (חוקים, אובייקטים, משתמשים)
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
    
    # בסיס נתונים נפרד ללוגים (לשיפור ביצועים ומניעת ניפוח ה-DB הראשי)
    SQLALCHEMY_BINDS = {
        'logs': f'sqlite:///{logs_db_path}'
    }
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False