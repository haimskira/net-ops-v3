"""
Expert Full-Stack Software Architecture: SyncManager.
Handles stateless synchronization between PAN-OS and local SQLite.
Optimized for deep object resolution and search accuracy.
"""

import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any, Optional, Union, Set, Tuple
from managers.models import (
    ServiceObject, db_sql, AddressObject, SecurityRule, 
    NetworkInterface, AuditLog, address_group_members,
    rule_source_map, rule_dest_map, rule_service_map
)
from panos.firewall import Firewall

class SyncManager:
    """
    מנהל סנכרון Stateless. 
    פותר בעיות UNIQUE constraint ע"י ניהול סטים של קישורים בזיכרון.
    מבצע רזולוציה של כתובות IP בזמן אמת לתוך שדה ה-value.
    """
    _sync_lock: bool = False
    _last_sync_time: float = 0
    _sync_interval: int = 300 

    def __init__(self, fw_connection: Firewall):
        """אתחול עם חיבור קיים לפיירוול."""
        self.fw = fw_connection

    def sync_all(self, fw_config: Dict[str, List[Dict[str, Any]]]) -> bool:
        """
        מבצע סנכרון מלא: ניקוי DB, הזרקת אובייקטים, קבוצות וחוקים.
        """
        if SyncManager._sync_lock: 
            return False
            
        try:
            SyncManager._sync_lock = True
            print("🔄 Starting Stateless Firewall Sync (Clean Association Flow)...")

            # ניקוי Context של SQLAlchemy
            db_sql.session.expunge_all()
            
            with db_sql.session.no_autoflush:
                # 1. ניקוי מוחלט של טבלאות אינוונטר וקישורים (Order matters for Foreign Keys)
                db_sql.session.execute(address_group_members.delete())
                db_sql.session.execute(rule_source_map.delete())
                db_sql.session.execute(rule_dest_map.delete())
                db_sql.session.execute(rule_service_map.delete())
                
                db_sql.session.query(SecurityRule).delete()
                db_sql.session.query(AddressObject).delete()
                db_sql.session.query(ServiceObject).delete()
                db_sql.session.flush()
                
                # 2. אובייקטים ושירותים בסיסיים (Address & Service)
                addr_map = self.sync_address_objects(fw_config.get('address', []))
                svc_map = self.sync_service_objects(fw_config.get('service', []))
                db_sql.session.flush()

                # 3. קבוצות כתובות (Address Groups)
                self.sync_address_groups(fw_config.get('address-group', []), addr_map)
                db_sql.session.flush()

                # 4. חוקי אבטחה (Security Rules)
                self.sync_security_rules(fw_config.get('rules', []), addr_map, svc_map)

                # 5. טופולוגיית רשת (Interfaces & Zones)
                self.sync_network_topology()

            db_sql.session.commit()
            SyncManager._last_sync_time = time.time()
            print(f"✅ Sync Success: {datetime.now().strftime('%H:%M:%S')}")
            return True
            
        except Exception as e:
            db_sql.session.rollback()
            print(f"❌ Sync Error: {str(e)}")
            return False
        finally:
            SyncManager._sync_lock = False

    def sync_address_objects(self, addr_list: List[Dict[str, Any]]) -> Dict[str, int]:
        name_to_id = {}
        for item in addr_list:
            name = item.get('name')
            if not name or name.lower() in name_to_id: continue
            
            # ניסיון חילוץ IP מכל המפתחות האפשריים ב-SDK
            val = (item.get('ip-netmask') or item.get('ip_netmask') or 
                item.get('ip-range') or item.get('ip_range') or 
                item.get('fqdn') or item.get('value') or 'any')
            
            # אם זה רשימה, ניקח את האיבר הראשון
            if isinstance(val, list) and len(val) > 0: val = val[0]

            obj = AddressObject(name=name, type='host', value=str(val), is_group=False)
            db_sql.session.add(obj)
            db_sql.session.flush() 
            name_to_id[name.lower()] = obj.id
        return name_to_id

    def sync_service_objects(self, svc_list: List[Dict[str, Any]]) -> Dict[str, int]:
        """סנכרון אובייקטי שירות (פורטים)."""
        name_to_id = {}
        for item in svc_list:
            name = item.get('name')
            if not name or name.lower() in name_to_id: 
                continue
                
            port_val = item.get('destination-port') or item.get('destination_port') or 'any'
            
            obj = ServiceObject(
                name=name, 
                protocol=item.get('protocol', 'tcp'), 
                port=str(port_val)
            )
            db_sql.session.add(obj)
            db_sql.session.flush()
            name_to_id[name.lower()] = obj.id
        return name_to_id

    def sync_address_groups(self, group_list: List[Dict[str, Any]], addr_map: Dict[str, int]) -> None:
        group_id_map = {}
        for g in group_list:
            name = g.get('name')
            if not name or name.lower() in addr_map: continue
            obj = AddressObject(name=name, is_group=True, type='group', value='group')
            db_sql.session.add(obj)
            db_sql.session.flush()
            addr_map[name.lower()] = obj.id
            
            # ניסיון חילוץ חברים לפי מספר מפתחות אפשריים ב-SDK
            members = g.get('static') or g.get('static_value') or []
            group_id_map[name.lower()] = (obj, members)

        links = set()
        for g_name, (obj, members) in group_id_map.items():
            if isinstance(members, str): members = [members]
            for m_name in set(members):
                m_id = addr_map.get(m_name.lower())
                if m_id and (obj.id, m_id) not in links:
                    db_sql.session.execute(address_group_members.insert().values(parent_id=obj.id, member_id=m_id))
                    links.add((obj.id, m_id))

    def sync_security_rules(self, rules_list: List[Dict[str, Any]], addr_map: Dict[str, int], svc_map: Dict[str, int]) -> None:
        """סנכרון חוקי אבטחה וקישור Many-to-Many לאובייקטים."""
        processed_rules = set()
        for r in rules_list:
            name = r.get('name')
            if not name or name.lower() in processed_rules: 
                continue
            processed_rules.add(name.lower())

            # חילוץ Zones
            f_zones = r.get('fromzone') or r.get('from') or ['any']
            t_zones = r.get('tozone') or r.get('to') or ['any']
            f_z = f_zones[0] if (isinstance(f_zones, list) and f_zones) else 'any'
            t_z = t_zones[0] if (isinstance(t_zones, list) and t_zones) else 'any'

            rule = SecurityRule(
                name=name, 
                from_zone=str(f_z), 
                to_zone=str(t_z), 
                action=r.get('action', 'allow')
            )
            db_sql.session.add(rule)
            db_sql.session.flush()

            # קישור אובייקטים - שימוש ב-Set למניעת כפילויות בתוך אותו חוק
            for s in set(r.get('source', [])):
                o_id = addr_map.get(s.lower())
                if o_id: 
                    db_sql.session.execute(rule_source_map.insert().values(rule_id=rule.id, address_id=o_id))
            
            for d in set(r.get('destination', [])):
                o_id = addr_map.get(d.lower())
                if o_id: 
                    db_sql.session.execute(rule_dest_map.insert().values(rule_id=rule.id, address_id=o_id))

            for svc in set(r.get('service', [])):
                s_id = svc_map.get(svc.lower())
                if s_id: 
                    db_sql.session.execute(rule_service_map.insert().values(rule_id=rule.id, service_id=s_id))

    def sync_network_topology(self) -> None:
        """משיכת טופולוגיה (Interfaces) לטובת זיהוי Zone אוטומטי."""
        try:
            db_sql.session.query(NetworkInterface).delete()
            # XML API for interfaces
            intf_res = self.fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet")
            intf_root = ET.fromstring(intf_res) if isinstance(intf_res, (str, bytes)) else intf_res
            
            iface_map = {}
            for entry in intf_root.findall(".//entry"):
                ifname = entry.get('name')
                ip_entry = entry.find(".//layer3/units/entry/ip/entry")
                if ip_entry is not None: 
                    iface_map[ifname] = ip_entry.get('name')

            zone_res = self.fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/network/zone")
            zone_root = ET.fromstring(zone_res) if isinstance(zone_res, (str, bytes)) else zone_res

            for zone in zone_root.findall(".//entry"):
                z_name = zone.get('name')
                for member in zone.findall(".//network/layer3/member"):
                    if member.text in iface_map:
                        db_sql.session.add(NetworkInterface(
                            name=member.text, 
                            subnet=iface_map[member.text], 
                            zone_name=z_name
                        ))
        except Exception as e:
            print(f"⚠️ Topology Sync Warning: {e}")