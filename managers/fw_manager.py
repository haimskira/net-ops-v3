import xml.etree.ElementTree as ET
import urllib3
import re
import time
from datetime import datetime, timedelta
from typing import Optional, Union, Dict, List, Any
from flask import session
from panos.firewall import Firewall
from panos.policies import SecurityRule, Rulebase
from config import Config
from managers.models import (
    db_sql, AddressObject, ServiceObject, 
    SecurityRule as DBSecurityRule, NetworkInterface
)
from netaddr import IPNetwork, IPAddress, IPRange, IPSet, AddrFormatError

# ביטול אזהרות SSL לסביבות פיתוח ורשתות סגורות
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CustomSecurityRule(SecurityRule):
    """
    מחלקה המרחיבה את SecurityRule של פאלו אלטו כדי לתמוך בשדה 'group-tag'
    שאינו נתמך כברירת מחדל בספריית pan-os-python.
    """
    def __init__(self, *args, **kwargs):
        self._group_tag = kwargs.pop('group_tag', None)
        super(CustomSecurityRule, self).__init__(*args, **kwargs)

    def element_str(self) -> str:
        """מייצר את מחרוזת ה-XML עבור החוק כולל ה-Group Tag המותאם."""
        root = super(CustomSecurityRule, self).element_str()
        if isinstance(root, (bytes, str)):
            root = ET.fromstring(root)
        if self._group_tag:
            gt_element = ET.Element('group-tag')
            gt_element.text = self._group_tag
            root.append(gt_element)
        return ET.tostring(root)

# --- פונקציות עזר לניהול משתמשים והרשאות ---

def get_username() -> str:
    """
    מחלץ שם משתמש מה-session בצורה בטוחה.
    תומך במבנה של אובייקט (דירוג) או מחרוזת פשוטה.
    """
    user_data = session.get('user')
    if isinstance(user_data, dict):
        return user_data.get('username', 'Unknown')
    return str(user_data) if user_data else 'Unknown'

def is_admin_check() -> bool:
    """
    בודק האם המשתמש הנוכחי הוא אדמין מורשה.
    """
    if session.get('is_admin'): 
        return True
    user_data = session.get('user')
    return isinstance(user_data, dict) and user_data.get('role') == 'admin'

def parse_expiration_from_tag(tag_name: Optional[str]) -> Optional[datetime]:
    """
    מחלץ ימי תוקף מטאג בתבנית 'X-G' (למשל 6-G עבור 6 ימים).
    """
    if not tag_name:
        return None
    match = re.search(r'(\d+)-G', tag_name)
    if match:
        days = int(match.group(1))
        return datetime.utcnow() + timedelta(days=days)
    return None

# --- לוגיקת IP Engine וניקוי נתונים ---

def sanitize_ip_input(val: str) -> str:
    """מנקה רווחים ותווים לא חוקיים מקלט ה-IP."""
    if not val: return ""
    return re.sub(r'[^0-9\.\-\/]', '', val)

def parse_ip_to_set(ip_str: str) -> IPSet:
    """
    ממיר מחרוזת (IP, Range, או CIDR) לאובייקט IPSet של netaddr.
    """
    ip_str = sanitize_ip_input(ip_str.strip())
    try:
        if '-' in ip_str:
            start_ip, end_ip = ip_str.split('-')
            return IPSet(IPRange(IPAddress(start_ip.strip()), IPAddress(end_ip.strip())))
        if ip_str:
            return IPSet(IPNetwork(ip_str if '/' in ip_str else f"{ip_str}/32"))
    except (AddrFormatError, ValueError):
        pass
    return IPSet()

def flatten_address_to_set(obj_name: str, depth: int = 0) -> IPSet:
    """
    מפרק אובייקטים וקבוצות (Address Groups) מה-DB באופן רקורסיבי ל-IPSet אחד.
    מוגבל לעומק 10 למניעת לולאות אינסופיות.
    """
    if depth > 10 or not obj_name: 
        return IPSet()
    if obj_name.lower() == 'any': 
        return IPSet(['0.0.0.0/0'])
    
    # שליפה מה-DB המקומי (Infrastructure Layer)
    db_obj = AddressObject.query.filter_by(name=obj_name).first()
    
    if not db_obj:
        # אם האובייקט לא ב-DB, ננסה לפענח ככתובת IP ישירה
        return parse_ip_to_set(obj_name)

    if db_obj.is_group:
        combined_set = IPSet()
        for member in db_obj.members:
            combined_set.update(flatten_address_to_set(member.name, depth + 1))
        return combined_set
    
    return parse_ip_to_set(db_obj.value or obj_name)

# --- פונקציות תשתית וחיבור לפיירוול ---

def get_fw_connection() -> Firewall:
    """מייצר חיבור לפיירוול על בסיס נתוני ה-Config."""
    if not Config.FW_IP or not Config.API_KEY:
        raise ValueError("Missing FW configurations (FW_IP or PA_API_KEY)")
    return Firewall(Config.FW_IP, api_key=Config.API_KEY, verify=False, timeout=60)

def load_app_ids() -> bool:
    """פונקציית תאימות עבור אתחול המערכת ב-app.py."""
    print("V App-IDs infrastructure ready.")
    return True

def refresh_fw_cache(force: bool = False) -> bool:
    """פונקציית תאימות עבור app.py; בגרסה זו מומלץ להשתמש ב-SyncManager לעדכון ה-DB."""
    print("🔄 Legacy Cache refresh wrapper called.")
    return True

def ensure_service_object(fw: Firewall, port: str, proto: str) -> str:
    """
    מוודא קיום אובייקט שירות בפיירוול. אם אינו קיים ב-DB, הוא נוצר בפיירוול.
    """
    proto = proto.lower()
    if not str(port).isdigit(): return port
    obj_name = f"service-{proto}-{port}"
    try:
        svc = ServiceObject.query.filter_by(name=obj_name).first()
        if not svc:
            from panos.objects import ServiceObject as PanServiceObject
            new_svc = PanServiceObject(name=obj_name, protocol=proto, destination_port=str(port))
            fw.add(new_svc)
            new_svc.create()
    except Exception as e:
        print(f"Error ensuring service object: {e}")
    return obj_name

# --- מנוע ה-Shadow Rule Check המשודרג ---

def check_shadow_rule(source: str, dest: str, service_port: str, 
                      protocol: str, from_zone: str, to_zone: str, 
                      application: str = 'any') -> Dict[str, Any]:
    """
    מנוע ה-Policy Match: בודק האם תעבורה כבר מכוסה על ידי חוק קיים ב-DB.
    תומך בבדיקה ללא Zone ובקבוצות כתובות.
    """
    try:
        # 1. הכנת הנתונים לבדיקה
        user_src_set = flatten_address_to_set(source)
        user_dst_set = flatten_address_to_set(dest)
        
        if not user_src_set or not user_dst_set:
            return {"exists": False, "message": "Invalid source or destination"}

        # 2. סינון חוקים רלוונטיים (רק אלו שאינם כבויים)
        query = DBSecurityRule.query.filter_by(disabled=False)
        
        # פילטור לפי Zones אם סופקו (תומך ב-Shadow Check חכם ללא Zone)
        if from_zone and from_zone != 'any':
            query = query.filter(DBSecurityRule.from_zone.in_([from_zone, 'any']))
        if to_zone and to_zone != 'any':
            query = query.filter(DBSecurityRule.to_zone.in_([to_zone, 'any']))

        possible_rules = query.all()

        # 3. בדיקת הצלבה (Subset Check) ברמת ה-IP
        for rule in possible_rules:
            # בדיקת Source
            r_src_set = IPSet()
            for s in rule.sources:
                r_src_set.update(flatten_address_to_set(s.name))
            if not user_src_set.issubset(r_src_set): continue

            # בדיקת Destination
            r_dst_set = IPSet()
            for d in rule.destinations:
                r_dst_set.update(flatten_address_to_set(d.name))
            if not user_dst_set.issubset(r_dst_set): continue

            # אם הגענו לכאן - נמצאה חפיפה מלאה
            return {
                "exists": True, 
                "rule_name": rule.name, 
                "action": rule.action,
                "full_data": {
                    "name": rule.name,
                    "from": rule.from_zone,
                    "to": rule.to_zone,
                    "action": rule.action
                }
            }

        return {"exists": False}
    except Exception as e:
        print(f"Shadow Check Error: {e}")
        return {"exists": False, "error": str(e)}

def find_zone_for_input(user_input: str) -> Optional[Union[str, List[str]]]:
    """
    מזהה Zone אוטומטית עבור IP או אובייקט על בסיס טבלת ה-NetworkInterface.
    חיוני עבור ה-Rule Manager.
    """
    try:
        # הפיכת הקלט ל-IPSet (מטפל בשמות אובייקטים, קבוצות וכתובות חופשיות)
        target_set = flatten_address_to_set(user_input)
        if not target_set: return None

        # שליפת טופולוגיית רשת מה-DB
        interfaces = NetworkInterface.query.all()
        detected_zones = set()

        for ip in target_set.iter_cidrs():
            found_for_this_cidr = False
            for iface in interfaces:
                if not iface.subnet: continue
                
                iface_net = IPNetwork(iface.subnet)
                # בדיקת הכללה (Overlap)
                if ip in iface_net or iface_net in ip:
                    detected_zones.add(iface.zone_name)
                    found_for_this_cidr = True
                    break
            
            if not found_for_this_cidr:
                return None # מחייב הזנה ידנית אם חלק מהטווח לא מזוהה

        if len(detected_zones) > 1: 
            return list(detected_zones) # המשתמש יצטרך לבחור
        
        return list(detected_zones)[0] if detected_zones else None

    except Exception as e:
        print(f"Error in find_zone_for_input: {e}")
        return None