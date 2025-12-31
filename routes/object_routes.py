"""
Expert Full-Stack Software Architecture: Objects Blueprint.
Validation: Migrated from Regex to 'ipaddress' library for robust IP/Subnet checking.
Zero Truncation: Full functional file provided.
"""

import ipaddress
import re
import traceback
from datetime import datetime
from flask import Blueprint, request, jsonify, session
from sqlalchemy import func, or_

# מנהלים ומודלים
from managers.fw_manager import get_fw_connection, get_username, is_admin_check
from managers.models import db_sql, ObjectRequest, AddressObject, ServiceObject, AuditLog

# Palo Alto SDK
from panos.objects import (
    AddressObject as PanAddress, 
    AddressGroup as PanAddressGroup, 
    ServiceObject as PanService, 
    ServiceGroup as PanServiceGroup
)

objects_bp = Blueprint('objects', __name__)

def validate_object_input(obj_type: str, value: str, protocol: str = None) -> (bool, str):
    """
    מבצע ולידציה לערכים לפני כניסה לבסיס הנתונים.
    שימוש בספריית ipaddress לכתובות ו-isnumeric לפורטים.
    """
    if not value:
        return False, "ערך האובייקט אינו יכול להיות ריק."

    value = str(value).strip()

    if obj_type == 'address':
        # 1. בדיקה אם מדובר בכתובת IP או Subnet תקינים
        try:
            # מטפל בכתובות בודדות ובפורמט CIDR (למשל 10.0.0.1/24)
            ipaddress.ip_interface(value)
            return True, ""
        except ValueError:
            # 2. אם לא IP, בודק אם זה Hostname (FQDN) תקין בסיסית
            if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]+[a-zA-Z0-9]$', value):
                return True, ""
            return False, "פורמט כתובת לא תקין. הזן IP חוקי או Hostname."

    elif obj_type == 'service':
        # ניקוי רווחים לבדיקת פורטים
        clean_ports = value.replace(" ", "")
        
        # בדיקה שהפורמט הבסיסי תקין (מספרים, פסיקים ומקפים)
        if not re.match(r'^\d+(-\d+)?(,\d+(-\d+)?)*$', clean_ports):
            return False, "פורמט פורטים לא תקין. דוגמה: 80 או 80-81 או 80,443."

        # בדיקה לוגית של ערכי הפורטים
        ports_to_check = clean_ports.replace('-', ',').split(',')
        for p in ports_to_check:
            if not p.isdigit():
                return False, f"ערך פורט לא חוקי: {p}"
            port_num = int(p)
            if not (1 <= port_num <= 65535):
                return False, f"הפורט {port_num} מחוץ לטווח החוקי (1-65535)."
        
        return True, ""

    # במידה ומדובר בקבוצה, הוולידציה מתבצעת ברמת ה-Frontend/Route
    return True, ""

@objects_bp.route('/create-object', methods=['POST'])
def create_object_request():
    """יוצר בקשה חדשה לאובייקט שתישלח לאישור אדמין."""
    data = request.json
    try:
        obj_type = data.get('type')
        value = str(data.get('value', '')).strip()
        name = str(data.get('name', '')).strip()
        protocol = data.get('protocol', 'tcp')

        # ולידציה מבוססת ipaddress ורכיבי פייתון
        is_valid, err_msg = validate_object_input(obj_type, value, protocol)
        if not is_valid:
            return jsonify({"status": "error", "message": err_msg}), 400

        new_req = ObjectRequest(
            name=name,
            obj_type=obj_type,
            value=value,
            prefix=data.get('prefix'),
            protocol=protocol,
            requested_by=get_username(),
            status='Pending',
            request_time=datetime.now()
        )
        db_sql.session.add(new_req)
        db_sql.session.commit()
        return jsonify({"status": "success", "message": "בקשת האובייקט נשלחה לאישור אדמין!"})
    except Exception as e:
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": f"שגיאת שרת: {str(e)}"}), 500

@objects_bp.route('/get-admin-view-objects')
def get_admin_objects():
    """שליפת כל האובייקטים (כולל היסטוריה) עבור האדמין."""
    if not is_admin_check(): 
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    all_reqs = ObjectRequest.query.order_by(ObjectRequest.id.desc()).all()
    return jsonify([{
        "id": o.id, 
        "name": o.name, 
        "obj_type": o.obj_type, 
        "value": o.value,
        "prefix": o.prefix, 
        "protocol": o.protocol,
        "requested_by": o.requested_by, 
        "status": o.status,
        "admin_notes": o.admin_notes,
        "request_time": o.request_time.strftime("%d/%m/%y %H:%M") if o.request_time else "N/A"
    } for o in all_reqs])

@objects_bp.route('/get-my-objects')
def get_my_objects_status():
    """שליפת סטטוס בקשות האובייקטים של המשתמש המחובר."""
    username = get_username()
    reqs = ObjectRequest.query.filter_by(requested_by=username).order_by(ObjectRequest.id.desc()).all()
    return jsonify([{
        "id": r.id, 
        "name": r.name, 
        "obj_type": r.obj_type, 
        "value": r.value or "",
        "prefix": r.prefix, 
        "protocol": r.protocol, 
        "status": r.status,
        "admin_notes": r.admin_notes,
        "request_time": r.request_time.strftime("%d/%m/%Y %H:%M") if r.request_time else ""
    } for r in reqs])

@objects_bp.route('/approve-object/<int:obj_id>', methods=['POST'])
def approve_object(obj_id: int):
    """
    מאשר אובייקט ויוצר אותו פיזית בפיירוול.
    תיקון: הוספת תיעוד Audit Log מלא (Resource Type ו-Details) למניעת ערכי None.
    """
    if not is_admin_check(): 
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    obj_req = ObjectRequest.query.get(obj_id)
    if not obj_req or obj_req.status != 'Pending':
        return jsonify({"status": "error", "message": "בקשה לא נמצאה או כבר טופלה"}), 404

    try:
        fw = get_fw_connection()
        t, n, v = obj_req.obj_type, obj_req.name, str(obj_req.value).strip()
        new_pan_obj = None

        if t == 'address':
            val_with_mask = f"{v}/{obj_req.prefix}" if obj_req.prefix and obj_req.prefix != '0' else (v if '/' in v else f"{v}/32")
            new_pan_obj = PanAddress(name=n, value=val_with_mask)
            if not AddressObject.query.filter_by(name=n).first():
                db_sql.session.add(AddressObject(name=n, value=val_with_mask, type='ip-netmask', is_group=False))

        elif t == 'address-group':
            members = [m.strip() for m in v.split(',') if m.strip()]
            new_pan_obj = PanAddressGroup(name=n, static_value=members)
            if not AddressObject.query.filter_by(name=n).first():
                db_sql.session.add(AddressObject(name=n, type='group', is_group=True))

        elif t == 'service':
            clean_port = v.replace(" ", "")
            new_pan_obj = PanService(name=n, protocol=obj_req.protocol or 'tcp', destination_port=clean_port)
            if not ServiceObject.query.filter_by(name=n).first():
                db_sql.session.add(ServiceObject(name=n, protocol=obj_req.protocol or 'tcp', port=clean_port))

        elif t == 'service-group':
            members = [m.strip() for m in v.split(',') if m.strip()]
            if not members:
                return jsonify({"status": "error", "message": "קבוצת שירותים לא יכולה להיות ריקה"}), 400
            
            new_pan_obj = PanServiceGroup(name=n, value=members)
            
            if not ServiceObject.query.filter_by(name=n).first():
                db_sql.session.add(ServiceObject(name=n, is_group=True))

        if new_pan_obj:
            fw.add(new_pan_obj)
            try:
                new_pan_obj.create()
            except Exception as xapi_err:
                print(f"--- FW XAPI ERROR for {n} ---")
                traceback.print_exc() 
                db_sql.session.rollback()
                return jsonify({"status": "error", "message": f"שגיאת פיירוול: {str(xapi_err)}"}), 400

        # עדכון סטטוס הבקשה
        obj_req.status = 'Approved'
        obj_req.processed_by = get_username()

        # קביעת סוג המשאב עבור ה-Audit Log בצורה ברורה (מניעת None)
        type_labels = {
            'address': 'Address Object',
            'address-group': 'Address Group',
            'service': 'Service Object',
            'service-group': 'Service Group'
        }
        res_type = type_labels.get(t, "Infrastructure Object")

        # הוספת רשומה ל-Audit Log עם כל השדות הנדרשים
        audit_entry = AuditLog(
            user=get_username(),
            action="APPROVE_OBJECT",
            resource_type=res_type,
            resource_name=n,
            details=f"Object Type: {t}, Value/Members: {v}"
        )
        db_sql.session.add(audit_entry)
        
        db_sql.session.commit()
        return jsonify({"status": "success", "message": f"האובייקט {n} נוצר בהצלחה."})

    except Exception as e:
        print(f"--- CRITICAL SYSTEM ERROR ---")
        traceback.print_exc()
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": f"שגיאת מערכת: {str(e)}"}), 500
    
        
@objects_bp.route('/reject-object/<int:obj_id>', methods=['POST'])
def reject_object(obj_id: int):
    """דחיית בקשת אובייקט."""
    if not is_admin_check(): return jsonify({"status": "error"}), 403
    
    data = request.json or {}
    obj_req = ObjectRequest.query.get(obj_id)
    if obj_req:
        obj_req.status = 'Rejected'
        obj_req.admin_notes = data.get('reason', 'נדחה על ידי אדמין')
        obj_req.processed_by = get_username()
        db_sql.session.add(AuditLog(user=get_username(), action="REJECT_OBJECT", resource_name=obj_req.name))
        db_sql.session.commit()
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 404

@objects_bp.route('/update-pending-object/<int:obj_id>', methods=['POST'])
def update_pending_object(obj_id: int):
    """עדכון אובייקט ע"י אדמין לפני אישור."""
    if not is_admin_check(): return jsonify({"status": "error"}), 403
    
    obj_req = ObjectRequest.query.get(obj_id)
    if not obj_req or obj_req.status != 'Pending':
        return jsonify({"status": "error", "message": "לא ניתן לערוך"}), 400

    data = request.json
    try:
        obj_req.name = data.get('name', obj_req.name)
        obj_req.value = data.get('value', obj_req.value)
        obj_req.prefix = data.get('prefix', obj_req.prefix)
        obj_req.protocol = data.get('protocol', obj_req.protocol)
        
        is_valid, err_msg = validate_object_input(obj_req.obj_type, obj_req.value, obj_req.protocol)
        if not is_valid:
            return jsonify({"status": "error", "message": err_msg}), 400
            
        db_sql.session.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@objects_bp.route('/get-address-objects')
def get_address_objects_list():
    objs = AddressObject.query.filter_by(is_group=False).all()
    return jsonify({"status": "success", "addresses": sorted([o.name for o in objs])})

@objects_bp.route('/get-service-objects')
def get_service_objects_list():
    objs = ServiceObject.query.filter_by(is_group=False).all()
    return jsonify({"status": "success", "services": sorted([o.name for o in objs])})