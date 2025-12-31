from flask import Blueprint, request, jsonify, session
from datetime import datetime
import traceback
from sqlalchemy import func, or_
from managers.fw_manager import get_fw_connection, get_username, is_admin_check
from managers.models import db_sql, ObjectRequest, AddressObject, ServiceObject, AuditLog
from panos.objects import (
    AddressObject as PanAddress, 
    AddressGroup as PanAddressGroup, 
    ServiceObject as PanService, 
    ServiceGroup as PanServiceGroup
)

objects_bp = Blueprint('objects', __name__)

@objects_bp.route('/create-object', methods=['POST'])
def create_object_request():
    """יוצר בקשה חדשה לאובייקט שתישלח לאישור אדמין."""
    data = request.json
    try:
        new_req = ObjectRequest(
            name=data.get('name'),
            obj_type=data.get('type'),
            value=data.get('value'),
            prefix=data.get('prefix'),
            protocol=data.get('protocol'),
            requested_by=get_username(), # שימוש בפונקציה המאוחדת
            status='Pending'
        )
        db_sql.session.add(new_req)
        db_sql.session.commit()
        return jsonify({"status": "success", "message": "בקשת האובייקט נשלחה לאישור אדמין!"})
    except Exception as e:
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@objects_bp.route('/get-admin-view-objects')
def get_admin_objects():
    """שליפת כל האובייקטים (כולל היסטוריה) עבור האדמין."""
    if not is_admin_check(): return jsonify([]), 403
    
    # שליפת היסטוריה מלאה, החדשים ביותר למעלה
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
    requests = ObjectRequest.query.filter_by(requested_by=username).order_by(ObjectRequest.id.desc()).all()
    
    results = []
    for r in requests:
        results.append({
            "id": r.id, 
            "name": r.name, 
            "obj_type": r.obj_type, 
            "value": r.value or "",
            "prefix": r.prefix, 
            "protocol": r.protocol, 
            "status": r.status,
            "admin_notes": r.admin_notes,
            "request_time": r.request_time.strftime("%d/%m/%Y %H:%M") if r.request_time else ""
        })
    return jsonify(results)

@objects_bp.route('/approve-object/<int:obj_id>', methods=['POST'])
def approve_object(obj_id: int):
    """
    מאשר אובייקט:
    1. יוצר פיזית בפיירוול (Palo Alto).
    2. מעדכן/יוצר באינוונטר המקומי (מניעת כפילויות).
    3. מעדכן סטטוס בקשה ורושם Audit Log.
    """
    if not is_admin_check(): return jsonify({"status": "error", "message": "Unauthorized"}), 403

    obj_req = ObjectRequest.query.get(obj_id)
    if not obj_req or obj_req.status != 'Pending':
        return jsonify({"status": "error", "message": "בקשה לא נמצאה או כבר טופלה"}), 404

    try:
        fw = get_fw_connection()
        t, n, v = obj_req.obj_type, obj_req.name, obj_req.value
        new_pan_obj = None

        # --- 1. יצירה בפיירוול וניהול אינוונטר מקומי ---
        
        if t == 'address':
            val_with_mask = f"{v}/{obj_req.prefix}" if obj_req.prefix else (v if '/' in v else f"{v}/32")
            new_pan_obj = PanAddress(name=n, value=val_with_mask)
            # Upsert לאינוונטר
            inv_exists = AddressObject.query.filter_by(name=n).first()
            if not inv_exists:
                db_sql.session.add(AddressObject(name=n, value=val_with_mask, type='ip-netmask', is_group=False))

        elif t == 'address-group':
            members = [m.strip() for m in v.split(',') if m.strip()]
            new_pan_obj = PanAddressGroup(name=n, static_value=members)
            inv_exists = AddressObject.query.filter_by(name=n).first()
            if not inv_exists:
                db_sql.session.add(AddressObject(name=n, type='group', is_group=True))

        elif t == 'service':
            new_pan_obj = PanService(name=n, protocol=obj_req.protocol or 'tcp', destination_port=str(v))
            inv_exists = ServiceObject.query.filter_by(name=n).first()
            if not inv_exists:
                db_sql.session.add(ServiceObject(name=n, protocol=obj_req.protocol or 'tcp', port=str(v)))

        elif t == 'service-group':
            members = [m.strip() for m in v.split(',') if m.strip()]
            new_pan_obj = PanServiceGroup(name=n, static_value=members)
            inv_exists = ServiceObject.query.filter_by(name=n).first()
            if not inv_exists:
                db_sql.session.add(ServiceObject(name=n, is_group=True))

        # ביצוע הפעולה מול הפיירוול
        if new_pan_obj:
            fw.add(new_pan_obj)
            new_pan_obj.create()

        # --- 2. עדכון סטטוס ותיעוד ---
        obj_req.status = 'Approved'
        obj_req.processed_by = get_username()
        
        audit = AuditLog(
            user=get_username(),
            action="APPROVE_OBJECT",
            resource_type="Object",
            resource_name=n,
            details=f"Type: {t}, Value: {v}"
        )
        db_sql.session.add(audit)
        
        db_sql.session.commit()
        return jsonify({"status": "success", "message": f"האובייקט {n} נוצר בהצלחה."})

    except Exception as e:
        db_sql.session.rollback()
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"FW Error: {str(e)}"}), 500

@objects_bp.route('/reject-object/<int:obj_id>', methods=['POST'])
def reject_object(obj_id: int):
    """דחיית אובייקט עם רישום סיבה."""
    if not is_admin_check(): return jsonify({"status": "error"}), 403
    
    data = request.json or {}
    reason = data.get('reason', 'נדחה על ידי אדמין')
    
    obj_req = ObjectRequest.query.get(obj_id)
    if obj_req:
        obj_req.status = 'Rejected'
        obj_req.admin_notes = reason
        obj_req.processed_by = get_username()
        
        db_sql.session.add(AuditLog(
            user=get_username(),
            action="REJECT_OBJECT",
            resource_name=obj_req.name,
            details=f"Reason: {reason}"
        ))
        
        db_sql.session.commit()
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 404

@objects_bp.route('/update-pending-object/<int:obj_id>', methods=['POST'])
def update_pending_object(obj_id: int):
    """עדכון פרטי אובייקט ע"י אדמין לפני אישור סופי."""
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
        db_sql.session.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@objects_bp.route('/get-address-objects')
def get_address_objects_list():
    """שליפת אובייקטים קיימים מה-Inventory לצורך בניית קבוצות ב-Frontend."""
    objs = AddressObject.query.filter_by(is_group=False).all()
    return jsonify({"status": "success", "addresses": sorted([o.name for o in objs])})

@objects_bp.route('/get-service-objects')
def get_service_objects_list():
    """שליפת שירותים קיימים מה-Inventory."""
    objs = ServiceObject.query.filter_by(is_group=False).all()
    return jsonify({"status": "success", "services": sorted([o.name for o in objs])})