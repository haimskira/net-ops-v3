from flask import Blueprint, request, jsonify, session
from datetime import datetime, timedelta
import re
import traceback
from sqlalchemy import func, or_
from managers.models import (
    db_sql, RuleRequest, SecurityRule, AddressObject, 
    ServiceObject, AuditLog, address_group_members
)
from managers.fw_manager import (
    get_fw_connection, CustomSecurityRule, 
    ensure_service_object
)
from panos.policies import Rulebase

rules_bp = Blueprint('rules', __name__)

# --- פונקציות עזר (Core Logic Helpers) ---

def get_username() -> str:
    """
    מחלץ שם משתמש מה-session בצורה בטוחה.
    תומך במבנה נתונים מסוג מילון (User Object) או מחרוזת פשוטה.
    """
    user_data = session.get('user')
    if isinstance(user_data, dict):
        return user_data.get('username', 'Unknown')
    return str(user_data) if user_data else 'Unknown'

def is_admin_check() -> bool:
    """
    בדיקת הרשאות מנהל (RBAC).
    מוודא שהמשתמש מורשה לבצע פעולות אישור/דחייה/עריכה.
    """
    if session.get('is_admin'): 
        return True
    user_data = session.get('user')
    return isinstance(user_data, dict) and user_data.get('role') == 'admin'

def parse_expiration_from_tag(tag_name: str) -> datetime:
    """
    מחלץ תאריך תפוגה מתוך טאג תשתית (Naming Convention: X-G).
    למשל: '30-G' יחזיר תאריך של היום + 30 יום.
    """
    if not tag_name: 
        return None
    match = re.search(r'(\d+)-G', str(tag_name))
    if match:
        days = int(match.group(1))
        return datetime.utcnow() + timedelta(days=days)
    return None

def get_all_relevant_object_names(ip_address: str) -> list:
    """
    מבצע 'Reverse Lookup' ב-Inventory: מוצא את כל האובייקטים והקבוצות 
    שמכילים את כתובת ה-IP הנתונה. חיוני למנוע ה-Policy Match.
    """
    # 1. חיפוש אובייקטים ישירים לפי שם או ערך
    direct_objects = AddressObject.query.filter(
        or_(AddressObject.value == ip_address, AddressObject.name == ip_address)
    ).all()
    
    names = [obj.name for obj in direct_objects]
    
    # 2. חיפוש קבוצות המכילות את האובייקטים הללו (Recursive Link)
    if direct_objects:
        obj_ids = [obj.id for obj in direct_objects]
        groups = db_sql.session.query(AddressObject.name).join(
            address_group_members, AddressObject.id == address_group_members.c.parent_id
        ).filter(address_group_members.c.member_id.in_(obj_ids)).all()
        names.extend([g.name for g in groups])
    
    return list(set(names)) if names else [ip_address]

# --- נתיבי API (Business Logic) ---

@rules_bp.route('/create-rule', methods=['POST'])
def create_rule():
    """יצירת בקשת חוקה חדשה עם מניעת כפילויות בתוך תור הממתינים."""
    data = request.json
    try:
        # ולידציה של בקשה זהה ב-Pending
        existing = RuleRequest.query.filter_by(
            source_ip=data.get('source_ip'),
            destination_ip=data.get('destination_ip'),
            service_port=data.get('service_port'),
            status='Pending'
        ).first()
        
        if existing:
            return jsonify({"status": "error", "message": f"כבר קיימת בקשה זהה ממתינה (ID: {existing.id})"})

        new_req = RuleRequest(
            rule_name=data.get('rule_name'),
            requested_by=get_username(),
            from_zone=data.get('from_zone'),
            to_zone=data.get('to_zone'),
            source_ip=data.get('source_ip'),
            destination_ip=data.get('destination_ip'),
            service_port=data.get('service_port'),
            protocol=data.get('protocol', 'tcp'),
            application=data.get('application', 'any'),
            tag=data.get('tag'),
            group_tag=data.get('group_tag'),
            duration_hours=int(data.get('duration_hours', 48))
        )
        db_sql.session.add(new_req)
        db_sql.session.commit()
        return jsonify({"status": "success", "message": "הבקשה נשלחה בהצלחה לאישור"})
    except Exception as e:
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@rules_bp.route('/get-admin-view-rules')
def get_admin_view_rules():
    """שליפת כל הבקשות עבור ממשק הניהול של האדמין."""
    if not is_admin_check(): 
        return jsonify([]), 403
    
    requests = RuleRequest.query.order_by(RuleRequest.request_time.desc()).all()
    return jsonify([{
        "id": r.id,
        "rule_name": r.rule_name,
        "requested_by": r.requested_by,
        "from_zone": r.from_zone or 'any',
        "to_zone": r.to_zone or 'any',
        "source_ip": r.source_ip,
        "destination_ip": r.destination_ip,
        "application": r.application or 'any',
        "service_port": r.service_port or 'any',
        "protocol": r.protocol or 'tcp',
        "tag": r.tag,
        "group_tag": r.group_tag,
        "status": r.status,
        "admin_notes": r.admin_notes,
        "request_time": r.request_time.strftime("%d/%m/%Y %H:%M")
    } for r in requests])

@rules_bp.route('/update-pending-rule/<int:rule_id>', methods=['POST'])
def update_pending_rule(rule_id: int):
    """
    עדכון פרטי בקשה קיימת בסטטוס Pending.
    פותר את שגיאת ה-404 בזמן עריכה לפני אישור.
    """
    if not is_admin_check(): 
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    rule_req = RuleRequest.query.get(rule_id)
    if not rule_req or rule_req.status != 'Pending':
        return jsonify({"status": "error", "message": "ניתן לערוך רק בקשות ממתינות"}), 400

    data = request.json
    try:
        rule_req.rule_name = data.get('rule_name', rule_req.rule_name)
        rule_req.source_ip = data.get('source_ip', rule_req.source_ip)
        rule_req.destination_ip = data.get('destination_ip', rule_req.destination_ip)
        rule_req.from_zone = data.get('from_zone', rule_req.from_zone)
        rule_req.to_zone = data.get('to_zone', rule_req.to_zone)
        rule_req.service_port = data.get('service_port', rule_req.service_port)
        rule_req.protocol = data.get('protocol', rule_req.protocol)
        rule_req.application = data.get('application', rule_req.application)
        rule_req.tag = data.get('tag', rule_req.tag)
        rule_req.group_tag = data.get('group_tag', rule_req.group_tag)
        
        db_sql.session.commit()
        return jsonify({"status": "success", "message": "הבקשה עודכנה בהצלחה"})
    except Exception as e:
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@rules_bp.route('/check-shadow', methods=['POST'])
def check_shadow():
    """
    מנוע Policy Match מתקדם: בודק חפיפה של Source, Destination ופורט.
    """
    data = request.json
    src_input = data.get('source_ip')
    dst_input = data.get('destination_ip')
    port_input = str(data.get('service_port'))

    if not src_input or not dst_input:
        return jsonify({"status": "clear"})

    # רזולוציית שמות (IP -> Objects)
    src_names = get_all_relevant_names(src_input)
    dst_names = get_all_relevant_names(dst_input)

    # שאילתה לבדיקת חוקים קיימים ב-Inventory
    query = SecurityRule.query

    # סינון לפי Zones אם נבחרו
    if data.get('from_zone') and data.get('from_zone') != 'any':
        query = query.filter(SecurityRule.from_zone == data.get('from_zone'))
    if data.get('to_zone') and data.get('to_zone') != 'any':
        query = query.filter(SecurityRule.to_zone == data.get('to_zone'))

    # חיפוש חוקים שתופסים את ה-Source וה-Dest
    matches = query.filter(
        SecurityRule.sources.any(AddressObject.name.in_(src_names)),
        SecurityRule.destinations.any(AddressObject.name.in_(dst_names))
    ).all()

    # סינון משני בתוך הקוד לבדיקת פורט (כדי להיות מדויקים)
    shadowing_rules = []
    for rule in matches:
        # אם בחוק הקיים יש 'any' בשירות, או שהפורט המבוקש נמצא ברשימת השירותים של החוק
        svc_ports = [s.port for s in rule.services]
        if not rule.services or port_input in svc_ports or 'any' in svc_ports:
            shadowing_rules.append(rule.name)

    if shadowing_rules:
        return jsonify({
            "status": "shadowed",
            "message": f"שיבוב חוקה: קיימים {len(shadowing_rules)} חוקים שמאפשרים תעבורה זו",
            "rules": shadowing_rules
        })

    return jsonify({"status": "clear"})

@rules_bp.route('/approve-single-rule/<int:rule_id>', methods=['POST'])
def approve_single_rule(rule_id: int):
    """אישור חוקה: דחיפה לפיירוול ועדכון Inventory (כולל טיפול ב-UNIQUE constraints)."""
    if not is_admin_check(): 
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    rule_req = RuleRequest.query.get(rule_id)
    if not rule_req or rule_req.status != 'Pending':
        return jsonify({"status": "error", "message": "בקשה לא נמצאה או כבר טופלה"}), 404

    try:
        # 1. הכנת נתונים
        clean_name = re.sub(r'[^a-zA-Z0-9_\-]', '', rule_req.rule_name.replace(' ', '_'))
        final_rule_name = (clean_name if clean_name and clean_name[0].isalpha() else f"R_{clean_name}")[:63]
        expiration = parse_expiration_from_tag(rule_req.tag)

        # 2. דחיפה לפיירוול
        fw = get_fw_connection()
        svc_name = ensure_service_object(fw, str(rule_req.service_port), rule_req.protocol)
        
        rb = Rulebase()
        fw.add(rb)
        new_fw_rule = CustomSecurityRule(
            name=final_rule_name,
            fromzone=[rule_req.from_zone or 'any'],
            tozone=[rule_req.to_zone or 'any'],
            source=[rule_req.source_ip],
            destination=[rule_req.destination_ip],
            application=[rule_req.application or 'any'],
            service=[svc_name],
            action='allow',
            tag=[rule_req.tag] if rule_req.tag and rule_req.tag != "None" else [],
            group_tag=rule_req.group_tag
        )
        rb.add(new_fw_rule)
        new_fw_rule.create()

        # 3. עדכון Inventory מקומי (Idempotent Upsert)
        synced_rule = SecurityRule.query.filter_by(name=final_rule_name).first()
        if not synced_rule:
            synced_rule = SecurityRule(
                name=final_rule_name, from_zone=rule_req.from_zone or 'any',
                to_zone=rule_req.to_zone or 'any', action='allow',
                tag_name=rule_req.tag, expire_at=expiration
            )
            db_sql.session.add(synced_rule)
        else:
            synced_rule.from_zone = rule_req.from_zone or 'any'
            synced_rule.to_zone = rule_req.to_zone or 'any'
            synced_rule.expire_at = expiration

        db_sql.session.flush()

        # 4. קישור אובייקטים (Case-Insensitive Relation Mapping)
        def robust_link(identifier, target_list):
            if not identifier or identifier.lower() == 'any': return
            obj = AddressObject.query.filter(
                or_(func.lower(AddressObject.name) == identifier.lower(),
                    func.lower(AddressObject.value) == identifier.lower())
            ).first()
            if obj and obj not in target_list: target_list.append(obj)

        robust_link(rule_req.source_ip, synced_rule.sources)
        robust_link(rule_req.destination_ip, synced_rule.destinations)
        
        svc_obj = ServiceObject.query.filter(func.lower(ServiceObject.name) == svc_name.lower()).first()
        if svc_obj and svc_obj not in synced_rule.services: synced_rule.services.append(svc_obj)

        # 5. סגירת בקשה ורישום
        rule_req.status = 'Approved'
        rule_req.processed_by = get_username()
        db_sql.session.add(AuditLog(user=get_username(), action="APPROVE_RULE", resource_name=final_rule_name))
        
        db_sql.session.commit()
        return jsonify({"status": "success", "message": f"חוקה {final_rule_name} אושרה ונוצרה"})
    except Exception as e:
        db_sql.session.rollback()
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@rules_bp.route('/reject-single-rule/<int:rule_id>', methods=['POST'])
def reject_single_rule(rule_id: int):
    """דחיית בקשת חוקה עם סיבה."""
    if not is_admin_check(): return jsonify({"status": "error"}), 403
    rule_req = RuleRequest.query.get(rule_id)
    if rule_req:
        rule_req.status = 'Rejected'
        rule_req.admin_notes = request.json.get('reason', 'לא צוינה סיבה')
        rule_req.processed_by = get_username()
        db_sql.session.commit()
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 404

@rules_bp.route('/get-my-requests')
def get_my_requests():
    """שליפת בקשות עבור המשתמש הנוכחי."""
    requests = RuleRequest.query.filter_by(requested_by=get_username()).order_by(RuleRequest.request_time.desc()).all()
    return jsonify([{
        "id": r.id, "rule_name": r.rule_name, "source": r.source_ip,
        "destination": r.destination_ip, "service_port": r.service_port,
        "application": r.application, "status": r.status,
        "time": r.request_time.strftime("%H:%M")
    } for r in requests])


def get_all_relevant_names(input_val: str) -> list:
    """
    מבצע רזולוציה מלאה: מקבל IP או שם, ומחזיר את כל השמות הקשורים ב-DB.
    זהו הלב של ה-Policy Match.
    """
    if not input_val or input_val.lower() == 'any':
        return ['any']

    # 1. חיפוש אובייקטים שהשם שלהם תואם לקלט או שהערך שלהם תואם ל-IP
    objs = AddressObject.query.filter(
        or_(
            func.lower(AddressObject.name) == input_val.lower(),
            AddressObject.value == input_val
        )
    ).all()

    if not objs:
        return [input_val]

    all_names = set()
    obj_ids = []
    for o in objs:
        all_names.add(o.name)
        obj_ids.append(o.id)

    # 2. מציאת קבוצות שמכילות את האובייקטים הללו
    groups = db_sql.session.query(AddressObject.name).join(
        address_group_members, AddressObject.id == address_group_members.c.parent_id
    ).filter(address_group_members.c.member_id.in_(obj_ids)).all()
    
    for g in groups:
        all_names.add(g[0])

    return list(all_names)


