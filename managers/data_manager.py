import json
import os
from datetime import datetime
from collections import deque
from typing import List, Dict, Any, Optional, Union
from managers.models import db_sql, RuleRequest, ObjectRequest

# --- הגדרות לוגים ותשתיות ---
LOG_DIR: str = 'data/traffic_log'
LOG_FILENAME: str = 'traffic.json'
LOG_PATH: str = os.path.join(LOG_DIR, LOG_FILENAME)
MAX_LOG_SIZE: int = 100 * 1024 * 1024  # 100MB

class DataManager:
    """
    מנהל הנתונים המרכזי (Singleton). 
    אחראי על ניהול לוגי תעבורה, זיכרון מטמון זמני וניהול בקשות עבודה (Workflow).
    """
    _instance: Optional['DataManager'] = None

    def __new__(cls) -> 'DataManager':
        if cls._instance is None:
            cls._instance = super(DataManager, cls).__new__(cls)
            cls._instance.init_data()
        return cls._instance

    def init_data(self) -> None:
        """אתחול תשתיות, יצירת תיקיות לוגים ומנגנון Cache זמני."""
        self.app_id_map: Dict[str, str] = {}
        
        # מנגנון ה-Cache עבור חוקי פיירוול (Shadow Rules)
        self.fw_cache: Dict[str, Any] = {
            "rules": [],          # אובייקטי SecurityRule
            "addresses": [],      # אובייקטי AddressObject
            "addr_map": {},       # שם אובייקט -> IP
            "last_updated": 0     # Timestamp
        }

        # מנגנון Cache עבור פרמטרים של ה-UI (Zones, Services וכו')
        self.firewall_cache: Dict[str, Any] = {
            "data": None,
            "last_updated": 0
        }
        
        # יצירת תיקיית לוגים במידה ואינה קיימת
        if not os.path.exists(LOG_DIR):
            try:
                os.makedirs(LOG_DIR, exist_ok=True)
                print(f"[*] Created log directory: {LOG_DIR}")
            except Exception as e:
                print(f"[!] Error creating log directory: {e}")

    # --- ניהול לוגי תעבורה (Traffic Logs) ---

    def add_traffic_log(self, log_entry: Dict[str, Any]) -> None:
        """כתיבת לוג תעבורה לקובץ עם מנגנון רוטציה מובנה (100MB)."""
        try:
            # בדיקת רוטציה: מונע ניפוח קבצים מעבר לקיבולת האחסון
            if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) >= MAX_LOG_SIZE:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = os.path.join(LOG_DIR, f"traffic_{timestamp}.json")
                os.rename(LOG_PATH, backup_name)
                print(f"[*] Log rotated: {backup_name}")

            # כתיבה בפורמט JSON Lines ליעילות מקסימלית
            with open(LOG_PATH, 'a', encoding='utf-8') as f:
                json.dump(log_entry, f, ensure_ascii=False)
                f.write('\n')
                
        except Exception as e:
            print(f"Error writing traffic log: {e}")

    def get_traffic_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """קריאת הלוגים האחרונים בצורה יעילה ללא טעינת כל הקובץ לזיכרון."""
        if not os.path.exists(LOG_PATH):
            return []
        
        try:
            with open(LOG_PATH, 'r', encoding='utf-8') as f:
                # שימוש ב-deque מאפשר קריאה מהירה של הזנב (Tail) בלבד
                last_lines = deque(f, maxlen=limit)
                
                logs = []
                for line in last_lines:
                    line = line.strip()
                    if line:
                        try:
                            logs.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            
            return logs[::-1]  # החזרת המידע מהחדש לישן
            
        except Exception as e:
            print(f"Error reading traffic logs: {e}")
            return []

    # --- ניהול בקשות חוקה (Rule Requests Workflow) ---

    def add_pending_rule(self, data: Dict[str, Any]) -> None:
        """הוספת בקשת חוקה חדשה למסד הנתונים."""
        new_rule = RuleRequest(
            rule_name=data.get('rule_name'),
            requested_by=data.get('requested_by'),
            from_zone=data.get('from_zone'),
            to_zone=data.get('to_zone'),
            source_ip=data.get('source_ip'),
            destination_ip=data.get('destination_ip'),
            service_port=data.get('service_port'),
            protocol=data.get('protocol', 'tcp'),
            application=data.get('application'),
            tag=data.get('tag'),
            group_tag=data.get('group_tag'),
            status='Pending'
        )
        db_sql.session.add(new_rule)
        db_sql.session.commit()

    def get_admin_view_rules(self) -> List[RuleRequest]:
        """שליפת כל הבקשות עבור ממשק האדמין."""
        return RuleRequest.query.order_by(RuleRequest.request_time.desc()).all()

    def get_user_requests(self, username: str) -> List[RuleRequest]:
        """שליפת בקשות עבור משתמש ספציפי."""
        return RuleRequest.query.filter_by(requested_by=username).order_by(RuleRequest.request_time.desc()).all()

    def update_rule_status(self, rule_id: int, status: str, 
                           admin_name: Optional[str] = None, 
                           final_name: Optional[str] = None, 
                           notes: Optional[str] = None) -> bool:
        """עדכון סטטוס בקשת חוקה לאחר אישור או דחייה."""
        rule = RuleRequest.query.get(rule_id)
        if rule:
            rule.status = status
            if admin_name: rule.processed_by = admin_name
            if notes: rule.admin_notes = notes
            if final_name: rule.final_rule_name = final_name
            db_sql.session.commit()
            return True
        return False

    # --- ניהול בקשות אובייקטים (Object Requests Workflow) ---

    def add_pending_object(self, data: Dict[str, Any]) -> None:
        """הוספת בקשת אובייקט חדשה (Address/Service)."""
        new_obj = ObjectRequest(
            obj_type=data.get('type'),
            name=data.get('name'),
            value=data.get('value'),
            prefix=data.get('prefix'),
            protocol=data.get('protocol'),
            requested_by=data.get('requested_by'),
            status='Pending'
        )
        db_sql.session.add(new_obj)
        db_sql.session.commit()

    def get_admin_objects(self) -> List[ObjectRequest]:
        """שליפת כל בקשות האובייקטים הממתינות לאדמין."""
        return ObjectRequest.query.order_by(ObjectRequest.request_time.desc()).all()

    def get_user_objects(self, username: str) -> List[ObjectRequest]:
        """שליפת בקשות אובייקטים של משתמש ספציפי."""
        return ObjectRequest.query.filter_by(requested_by=username).order_by(ObjectRequest.request_time.desc()).all()

    def update_object_status(self, obj_id: int, status: str, 
                             admin_name: Optional[str] = None, 
                             notes: Optional[str] = None) -> bool:
        """עדכון סטטוס בקשת אובייקט."""
        obj = ObjectRequest.query.get(obj_id)
        if obj:
            obj.status = status
            if notes: obj.admin_notes = notes
            db_sql.session.commit()
            return True
        return False

    # --- תאימות לאחור (Wrappers) ---

    def add_object_request(self, data: Dict[str, Any]) -> None: 
        return self.add_pending_object(data)
    
    def get_user_object_requests(self, username: str) -> List[ObjectRequest]: 
        return self.get_user_objects(username)
    
    def get_pending_objects(self) -> List[ObjectRequest]: 
        return self.get_admin_objects()
    
    def get_object_request_by_id(self, obj_id: int) -> Optional[Dict[str, Any]]:
        """שליפת בקשת אובייקט בודדת כ-Dictionary."""
        obj = ObjectRequest.query.get(obj_id)
        if not obj: return None
        return {c.name: getattr(obj, c.name) for c in obj.__table__.columns}

    # --- ניטור ובקרה ---

    def log_action(self, user: str, action: str, target: str, details: str, ip: str) -> None:
        """תיעוד פעולה בטרמינל (ניתן להרחיב ל-Audit Log ב-DB)."""
        print(f"[ACTION] {datetime.now()} | User: {user} | Action: {action} | Target: {target} | IP: {ip}")

# ייצירת מופע Singleton יחיד לכל האפליקציה
db = DataManager()