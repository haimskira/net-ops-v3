from flask import Blueprint, render_template, request, redirect, url_for, session
from auth import authenticate_ldap
from config import Config 

# הגדרת ה-Blueprint
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 1. ניסיון התחברות דרך LDAP
        success = False
        is_admin = False
        
        try:
            success, is_admin = authenticate_ldap(username, password)
        except Exception as e:
            # אם שרת ה-LDAP למטה או שיש שגיאת תקשורת, אנחנו מדפיסים ללוג וממשיכים לבדיקה המקומית
            print(f"LDAP Authentication bypassed or failed: {e}")

        # 2. בדיקת Fallback למשתמש מקומי (Break-glass)
        # הבדיקה תתבצע רק אם ה-LDAP לא החזיר הצלחה
        if not success:
            local_user = getattr(Config, 'LOCAL_ADMIN_USER', None)
            local_pass = getattr(Config, 'LOCAL_ADMIN_PASS', None)

            # וודא שהגדרת משתנים ב-ENV כדי שלא יתאפשר חיבור ריק
            if local_user and local_pass:
                if username == local_user and password == local_pass:
                    success = True
                    is_admin = True # משתמש חירום מקומי נחשב אדמין
        
        # 3. ניהול ה-Session במקרה של הצלחה
        if success:
            session['user'] = username 
            session['is_admin'] = is_admin
            return redirect(url_for('main.main_page'))
        else:
            error = "שם משתמש או סיסמה שגויים (LDAP/Local)"
            
    return render_template('login.html', error=error)


@auth_bp.route('/logout')
def logout():
    session.clear()
    # הפניה חזרה ללוגין
    return redirect(url_for('auth.login'))