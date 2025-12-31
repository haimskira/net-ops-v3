"""
Expert Full-Stack Software Architecture: Operations & Monitoring Routes.
Handles Deep Object Resolution for Hover Tooltips and Smart Search.
"""

# 1. Standard Library Imports
import logging
import time
import traceback
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from datetime import datetime

# 2. Third-Party Library Imports
import requests
from flask import Blueprint, Response, jsonify, render_template, request, session

# 3. Pan-OS / Firewall SDK Imports (Aliases to prevent SQLAlchemy conflicts)
from panos.network import Zone
from panos.objects import (
    AddressGroup as PanAddressGroup, 
    AddressObject as PanAddressObject, 
    ServiceObject as PanServiceObject, 
    Tag as PanTag
)
from panos.policies import SecurityRule as PanSecurityRule, Rulebase

# 4. Local Application Imports (Project Specific)
from config import Config
from managers.data_manager import db
from managers.fw_manager import (
    get_fw_connection, 
    get_username, 
    is_admin_check, 
    refresh_fw_cache
)
from managers.models import (
    AddressObject, 
    AuditLog, 
    SecurityRule, 
    ServiceObject, 
    TrafficLog, 
    db_sql
)
from managers.sync_manager import SyncManager

# Initialize the Ops Blueprint
ops_bp = Blueprint('ops', __name__)

# --------------------------------------------------------------------------
# I. Helper Functions (Deep Resolution Logic)
# --------------------------------------------------------------------------

def resolve_object_content(obj: Any) -> List[str]:
    """
    פונקציה רקורסיבית ששולפת אך ורק את התוכן הטכני (IP/Port).
    משמשת לחיפוש החכם ולמערכת ה-Tooltip ב-Hover.
    """
    if not obj: 
        return []
        
    if not getattr(obj, 'is_group', False):
        # מחלץ IP מכתובת (field: value) או פורט משירות (field: port)
        val = getattr(obj, 'value', '') or getattr(obj, 'port', '')
        # מחזירים רק אם הערך קיים ואינו 'any'
        return [str(val)] if (val and str(val).lower() != 'any') else []
    
    # רקורסיה לקבוצות (Address Groups / Service Groups)
    res = []
    members = getattr(obj, 'members', [])
    for m in members:
        res.extend(resolve_object_content(m))
        
    return list(set(res)) # הסרת כפילויות

# --------------------------------------------------------------------------
# II. View Routes (Template Rendering)
# --------------------------------------------------------------------------

@ops_bp.route('/log-viewer')
def log_viewer_page() -> str:
    """Renders the Live Traffic Log Viewer."""
    return render_template('log_viewer.html')

@ops_bp.route('/audit-logs')
def audit_logs_page() -> str:
    """Renders System Audit Logs (Admin only)."""
    if not is_admin_check():
        return render_template('error.html', message="Unauthorized Access"), 403
    
    try:
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
        return render_template('audit.html', logs=logs)
    except Exception as e:
        logging.error(f"Audit Log Fetch Error: {str(e)}")
        return render_template('audit.html', logs=[])

@ops_bp.route('/policy-inventory')
def policy_inventory_page() -> str:
    """Renders the Firewall Policy Inventory dashboard."""
    if not is_admin_check():
        return render_template('error.html', message="Unauthorized Access"), 403
    return render_template('policy_viewer.html')


# --------------------------------------------------------------------------
# III. API Routes - Logging (Database Driven)
# --------------------------------------------------------------------------

@ops_bp.route('/get-live-logs')
def get_live_logs() -> Response:
    """Fetches traffic logs from the dedicated logs database bind."""
    try:
        logs = TrafficLog.query.order_by(TrafficLog.id.desc()).limit(100).all()
        formatted = []
        for log in logs:
            formatted.append({
                "time": log.time,
                "source": log.source,
                "destination": log.destination,
                "src_zone": log.src_zone or 'N/A',
                "dst_zone": log.dst_zone or 'N/A',
                "app": log.app or 'any',
                "protocol": log.protocol or 'tcp',
                "dst_port": str(log.dst_port or 'any'),
                "action": log.action or 'allow'
            })
        return jsonify(formatted)
    except Exception as e:
        logging.error(f"API Log Fetch Error: {str(e)}")
        return jsonify([])

@ops_bp.route('/api/clear-logs', methods=['POST'])
def clear_logs() -> Response:
    """Clears the traffic logs table in the database."""
    if not is_admin_check():
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    try:
        db_sql.session.query(TrafficLog).delete()
        db_sql.session.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------------------------
# IV. API Routes - Inventory & Advanced Resolution
# --------------------------------------------------------------------------

@ops_bp.route('/get-all-policies')
def get_all_policies() -> Response:
    """
    שליפת כל החוקים מה-DB המקומי.
    כולל הצלבה (Cross-Reference) של שמות אובייקטים לערכי IP/Port.
    """
    try:
        rules = SecurityRule.query.all()
        formatted_rules = []
        
        for r in rules:
            def format_collection(obj_list):
                if not obj_list:
                    return [{"name": "any", "value": "any", "is_group": False}]
                
                output = []
                for o in obj_list:
                    # שימוש בפונקציה המאוחדת resolve_object_content
                    tech_vals = resolve_object_content(o)
                    output.append({
                        "name": o.name,
                        "value": ", ".join(tech_vals) if tech_vals else "No IP in DB",
                        "is_group": getattr(o, 'is_group', False)
                    })
                return output

            formatted_rules.append({
                "name": r.name,
                "from": r.from_zone or 'any',
                "to": r.to_zone or 'any',
                "sources": format_collection(r.sources),
                "destinations": format_collection(r.destinations),
                "services": format_collection(r.services),
                "action": r.action or 'allow'
            })
        return jsonify(formatted_rules)
    except Exception as e:
        logging.error(f"Inventory API Error: {str(e)}")
        traceback.print_exc()
        return jsonify([]), 500
    

@ops_bp.route('/get-params', methods=['GET'])
def get_params() -> Response:
    """Fetches metadata (Zones, Apps, Tags) with memory caching."""
    current_time = time.time()
    if not hasattr(db, 'firewall_cache'):
        db.firewall_cache = {"data": None, "last_updated": 0}

    if db.firewall_cache["data"] and (current_time - db.firewall_cache["last_updated"] < 300):
        return jsonify(db.firewall_cache["data"])
        
    try:
        refresh_fw_cache()
        fw = get_fw_connection()
        
        zone_list = sorted([z.name for z in Zone.refreshall(fw) if z.name])
        svc_list = sorted([s.name for s in PanServiceObject.refreshall(fw) if s.name])
        
        if 'any' not in zone_list: zone_list.insert(0, 'any')
        if 'application-default' not in svc_list: svc_list.insert(0, 'application-default')

        addr_objs = PanAddressObject.refreshall(fw)
        group_objs = PanAddressGroup.refreshall(fw)
        
        address_map = {a.name: a.value for a in addr_objs if a.name}
        full_addr_list = sorted([a.name for a in addr_objs if a.name] + 
                                [g.name for g in group_objs if g.name])

        response_data = {
            "status": "success", 
            "zones": zone_list, 
            "services": svc_list, 
            "addresses": full_addr_list,
            "address_map": address_map,
            "address_groups": sorted([g.name for g in group_objs if g.name]),
            "applications": ["any", "web-browsing", "ssl", "dns", "ping", "ssh", "active-directory"], 
            "tags": sorted([t.name for t in PanTag.refreshall(fw) if t.name]) if PanTag else []
        }
        
        db.firewall_cache["data"] = response_data
        db.firewall_cache["last_updated"] = current_time
        return jsonify(response_data)
    except Exception as e:
        logging.error(f"Get Params API Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------------------------
# V. API Routes - Commit & Job Control
# --------------------------------------------------------------------------

@ops_bp.route('/commit', methods=['POST'])
def commit_changes() -> Response:
    """Triggers a configuration commit on the firewall."""
    if not is_admin_check():
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    try:
        fw = get_fw_connection()
        job_id = fw.commit(sync=False)
        return jsonify({"status": "success", "message": f"ה-Commit נשלח! (ג'וב מספר {job_id})."})
    except Exception as e:
        if "705" in str(e) or "704" in str(e):
            return jsonify({"status": "success", "message": "ה-Commit כבר מתבצע ברקע."})
        return jsonify({"status": "error", "message": str(e)}), 500

@ops_bp.route('/job-status/<int:job_id>')
def get_job_status(job_id: int) -> Response:
    """Monitors job progress via Firewall XML API."""
    try:
        url = f"https://{Config.FW_IP}/api/?type=op&cmd=<show><jobs><id>{job_id}</id></jobs></show>&key={Config.API_KEY}"
        r = requests.get(url, verify=False, timeout=10)
        root = ET.fromstring(r.text)
        job = root.find(".//job")
        if job is not None:
            return jsonify({
                "status": job.findtext("status"),
                "progress": job.findtext("progress"),
                "result": job.findtext("result")
            })
        return jsonify({"status": "not_found"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# --------------------------------------------------------------------------
# VI. Utility Tools (Match, Zone Detect & Sync)
# --------------------------------------------------------------------------

@ops_bp.route('/run-policy-match', methods=['POST'])
def run_policy_match() -> Response:
    """Tests traffic parameters against the firewall security engine."""
    data = request.json or {}
    try:
        source = data.get("source_ip", "").strip()
        destination = data.get("destination_ip", "").strip()
        port = data.get("port", "443").strip()
        
        cmd = (f"<test><security-policy-match>"
               f"<source>{source}</source><destination>{destination}</destination>"
               f"<protocol>6</protocol><destination-port>{port}</destination-port>"
               f"</security-policy-match></test>")
        
        url = f"https://{Config.FW_IP}/api/?type=op&cmd={cmd}&key={Config.API_KEY}&target-vsys=vsys1"
        r = requests.get(url, verify=False, timeout=15)
        xml_root = ET.fromstring(r.text)
        
        entry = xml_root.find(".//entry")
        if entry is not None:
            return jsonify({
                "status": "success", "match": True, 
                "rule_name": entry.get("name"), "action": entry.findtext("action") or "allow"
            })
        return jsonify({"status": "success", "match": False})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@ops_bp.route('/api/detect-zone', methods=['GET'])
def detect_zone() -> Response:
    """Predicts firewall zone for an IP based on local interface subnet mapping."""
    user_input = request.args.get('ip')
    if not user_input:
        return jsonify({"status": "error", "message": "Missing input"}), 400
    try:
        from managers.fw_manager import find_zone_for_input
        zone = find_zone_for_input(user_input)
        return jsonify({"status": "success", "zone": zone}) if zone else jsonify({"status": "unknown"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@ops_bp.route('/api/sync/firewall', methods=['POST'])
def trigger_firewall_sync() -> Response:
    """Manually refreshes the local DB inventory from live Firewall config."""
    if not is_admin_check():
        return jsonify({"status": "error", "message": "Admin only"}), 403

    try:
        fw = get_fw_connection()
        rb = Rulebase()
        fw.add(rb)
        
        fw_config = {
            'address': [obj.about() for obj in PanAddressObject.refreshall(fw)],
            'address-group': [obj.about() for obj in PanAddressGroup.refreshall(fw)],
            'service': [obj.about() for obj in PanServiceObject.refreshall(fw)],
            'rules': [obj.about() for obj in PanSecurityRule.refreshall(rb)]
        }

        sync_mgr = SyncManager(fw)
        if sync_mgr.sync_all(fw_config):
            audit = AuditLog(
                user=get_username(), action="MANUAL_SYNC", resource_type="System",
                resource_name="Firewall Inventory", details="Manual refresh of policy inventory."
            )
            db_sql.session.add(audit)
            db_sql.session.commit()
            return jsonify({"status": "success", "message": "הסנכרון הושלם בהצלחה!"})
        return jsonify({"status": "error", "message": "Sync failed."}), 409
    except Exception as e:
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500