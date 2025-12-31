import os
from ldap3 import Server, Connection, ALL, SUBTREE
from dotenv import load_dotenv

load_dotenv()

def authenticate_ldap(username, password):
    server_ip = os.getenv('LDAP_SERVER')
    domain = os.getenv('LDAP_DOMAIN')
    base_dn = os.getenv('LDAP_BASE_DN')
    admin_group = os.getenv('LDAP_ADMIN_GROUP', '').lower()
    user_group = os.getenv('LDAP_USER_GROUP', '').lower()
    
    print(f"--- Connection attempt for: {username} ---")
    
    try:
        server = Server(server_ip, get_info=ALL)
        user_principal_name = f"{username}@{domain}"
        
        # 1. Password Verification (Bind)
        # Note: If this works, a Service Account is not strictly required, but recommended later.
        conn = Connection(server, user=user_principal_name, password=password, auto_bind=True)
        print(f"V Password verification successful")
            
        # 2. User Search
        search_filter = f'(&(objectClass=person)(sAMAccountName={username}))'
        conn.search(search_base=base_dn, 
                    search_filter=search_filter, 
                    search_scope=SUBTREE, 
                    attributes=['memberOf', 'displayName'])
        
        if not conn.entries:
            print(f"X User not found in search.")
            return False, False

        entry = conn.entries[0]
        
        # --- Critical Fix: Handling Group List ---
        raw_groups = []
        if 'memberOf' in entry:
            # If there is only one group, ldap3 sometimes returns a string instead of a list
            val = entry.memberOf.value
            if isinstance(val, str):
                raw_groups = [val]
            else:
                raw_groups = val
        
        print(f"User found: {entry.displayName}")
        print(f"Found groups (processed):")
        
        user_groups_lower = []
        for g in raw_groups:
            g_lower = str(g).lower()
            user_groups_lower.append(g_lower)
            print(f" - {g_lower}")

        # 3. Check permissions against ENV variables
        is_admin = admin_group in user_groups_lower
        is_low_user = user_group in user_groups_lower

        if is_admin:
            print(f"V Authenticated as ADMIN")
            return True, True
        elif is_low_user:
            print(f"V Authenticated as USER")
            return True, False
        else:
            print(f"X Access denied: User is not in {admin_group} nor in {user_group}")
            return False, False
            
    except Exception as e:
        print(f"X Error: {e}")
        return False, False
    finally:
        if 'conn' in locals():
            conn.unbind()