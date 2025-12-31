import os
from pathlib import Path
from dotenv import load_dotenv
from typing import Dict, Optional

# טעינת משתני סביבה
load_dotenv()

class Config:
    """
    Expert-level Flask Configuration.
    Handles Multi-DB binding, LDAP integration, and environment-specific paths.
    """
    
    # --- Paths Management ---
    # שימוש ב-Pathlib לניהול נתיבים חוצה פלטפורמות
    BASE_DIR: Path = Path(__file__).resolve().parent
    
    # הגדרת נתיב הנתונים: אם קיים משתנה סביבה DATA_PATH (נפוץ ב-Docker), נשתמש בו.
    # אחרת, נשתמש בתיקיית instance מקומית.
    DATA_DIR: Path = Path(os.getenv('DATA_PATH', BASE_DIR / 'data'))
    
    # יצירת תיקיית הנתונים אם אינה קיימת (למניעת שגיאות SQLite)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # --- Flask Settings ---
    SECRET_KEY: str = os.getenv('FLASK_SECRET_KEY', 'change-me-in-production-12345')
    DEBUG: bool = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

    # --- Firewall (PAN-OS) ---
    FW_IP: Optional[str] = os.getenv('FW_IP')
    API_KEY: Optional[str] = os.getenv('PA_API_KEY')
    
    # --- Local Auth ---
    LOCAL_ADMIN_USER: str = os.getenv('LOCAL_ADMIN_USER', 'admin')
    LOCAL_ADMIN_PASS: Optional[str] = os.getenv('LOCAL_ADMIN_PASS')

    # --- Logging & Retention ---
    try:
        SYSLOG_PORT: int = int(os.getenv('SYSLOG_PORT', 514))
    except (ValueError, TypeError):
        SYSLOG_PORT = 514
        
    LOGS_DB_MAX_MB: int = 100

    # --- LDAP Configuration ---
    LDAP_SERVER: Optional[str] = os.getenv('LDAP_SERVER')
    LDAP_DOMAIN: Optional[str] = os.getenv('LDAP_DOMAIN')
    LDAP_BASE_DN: Optional[str] = os.getenv('LDAP_BASE_DN')
    LDAP_ADMIN_GROUP: Optional[str] = os.getenv('LDAP_ADMIN_GROUP')
    LDAP_USER_GROUP: Optional[str] = os.getenv('LDAP_USER_GROUP')

    # --- Database Configuration (Multi-DB Binding) ---
    # שימוש בנתיבים מוחלטים שנבנו ב-DATA_DIR
    _main_db: str = str(DATA_DIR / 'netops.db')
    _logs_db: str = str(DATA_DIR / 'traffic_logs.db')

    SQLALCHEMY_DATABASE_URI: str = f'sqlite:///{_main_db}'
    
    SQLALCHEMY_BINDS: Dict[str, str] = {
        'logs': f'sqlite:///{_logs_db}'
    }
    
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    @classmethod
    def validate_config(cls) -> None:
        """
        Pre-flight check to ensure critical environment variables are set.
        Raises ValueError if mandatory fields are missing.
        """
        required_vars = {
            'FW_IP': cls.FW_IP,
            'PA_API_KEY': cls.API_KEY,
            'LOCAL_ADMIN_PASS': cls.LOCAL_ADMIN_PASS
        }
        
        missing = [k for k, v in required_vars.items() if not v]
        if missing:
            raise ValueError(f"❌ Missing critical environment variables: {', '.join(missing)}")