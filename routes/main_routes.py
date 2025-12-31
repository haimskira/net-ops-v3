from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify
from managers.fw_manager import find_zone_for_input

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def main_page():
    """דף הבית המרכזי (Shell) המכיל את ה-Nav Bar וה-Iframes."""
    return render_template('main.html')

# --- APIs כלליים לממשק ---

@main_bp.route('/api/detect-zone')
def detect_zone():
    """
    מזהה Zone באופן אוטומטי על בסיס IP או שם אובייקט.
    משתמש בטבלת NetworkInterface שסונכרנה מהפיירוול.
   
    """
    ip_val = request.args.get('ip')
    if not ip_val or ip_val.lower() == 'any':
        return jsonify({"status": "success", "zone": "any"})
    
    try:
        # פנייה למנוע ה-Network ב-fw_manager
        detected = find_zone_for_input(ip_val)
        
        if detected:
            # אם נמצאו מספר אזורים, נחזיר את הראשון כברירת מחדל
            zone_result = detected[0] if isinstance(detected, list) else detected
            return jsonify({"status": "success", "zone": zone_result})
        
        return jsonify({"status": "error", "message": "Zone not found in DB topology"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- ניתוב דפים (Render Templates) ---

@main_bp.route('/palo-manager')
def palo_manager_app(): 
    return render_template('rule_manager.html')

@main_bp.route('/object-creator')
def object_creator_page(): 
    return render_template('create_object.html') # שם הקובץ שסידרנו

@main_bp.route('/log-viewer')
def log_viewer_page(): 
    return render_template('log_viewer.html')

@main_bp.route('/policy-match-tool')
def policy_match_page(): 
    return render_template('policy_match.html')

@main_bp.route('/admin-approval-tool')
def admin_approval_page():
    if not session.get('is_admin'): 
        return redirect(url_for('main.main_page'))
    return render_template('admin_approval.html')

@main_bp.route('/object-approval-tool')
def object_approval_page():
    if not session.get('is_admin'): 
        return redirect(url_for('main.main_page'))
    return render_template('object_approval.html')

@main_bp.route('/my-requests-tool')
def my_requests_page(): 
    return render_template('my_requests.html')

@main_bp.route('/my-objects-tool')
def my_objects_page(): 
    return render_template('my_objects.html')