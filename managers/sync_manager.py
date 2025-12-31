"""
Expert Full-Stack Software Architecture: SyncManager.
Handles stateless synchronization between PAN-OS and local SQLite.
Optimized for deep object resolution including Address and Service Groups.
"""

import logging
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any, Optional, Set

from managers.models import (
    ServiceObject, db_sql, AddressObject, SecurityRule, 
    NetworkInterface, AuditLog, address_group_members, service_group_members,
    rule_source_map, rule_dest_map, rule_service_map,
    ApplicationObject, rule_app_map
)
from panos.firewall import Firewall

class SyncManager:
    """
    מנהל סנכרון Stateless. 
    פותר בעיות UNIQUE constraint ע"י ניהול סטים של קישורים בזיכרון.
    מבצע רזולוציה של כתובות IP ופורטים בזמן אמת.
    """
    _sync_lock = threading.Lock()
    _last_sync_time: float = 0
    _sync_interval: int = 300 

    def __init__(self, fw_connection: Firewall):
        """
        אתחול עם חיבור קיים לפיירוול.
        
        :param fw_connection: אובייקט החיבור לפיירוול מבוסס PAN-OS SDK.
        """
        self.fw = fw_connection

    def sync_all(self, fw_config: Dict[str, List[Dict[str, Any]]]) -> bool:
        """
        מבצע סנכרון מלא: ניקוי DB, הזרקת אובייקטים, קבוצות (כתובות ושירותים) וחוקים.
        
        :param fw_config: דיקשנרי המכיל את כלל נתוני ה-Firewall (about format).
        :return: True אם הסנכרון הצליח.
        """
        if not SyncManager._sync_lock.acquire(blocking=False):
            logging.warning("⏳ Sync already in progress, skipping...")
            return False
            
        try:
            logging.info("🔄 Starting Stateless Firewall Sync (Deep Group Resolution)...")

            # ניקוי Context של SQLAlchemy למניעת התנגשויות זיכרון
            db_sql.session.expunge_all()
            
            with db_sql.session.no_autoflush:
                # 1. ניקוי מוחלט של טבלאות אינוונטר וקישורים (בסדר היררכי למניעת FK violations)
                self._clear_database()
                
                # 2. סנכרון ישויות בסיסיות (Atomic Objects + Group Objects)
                # שלב ראשון: יצירת כל הישויות כדי לקבל מפת IDs בזיכרון
                addr_map = self.sync_address_objects(
                    fw_config.get('address', []), 
                    fw_config.get('address-group', [])
                )
                svc_map = self.sync_service_objects(
                    fw_config.get('service', []), 
                    fw_config.get('service-group', [])
                )
                app_map = self.sync_application_objects(
                    fw_config.get('applications', []) or fw_config.get('application', [])
                )
                
                db_sql.session.flush()

                # 3. קישור חברי קבוצות (Resolution)
                # עכשיו כשכל ה-IDs קיימים, אפשר לקשר קבוצות לחברים (כולל Nested)
                self.link_address_groups(fw_config.get('address-group', []), addr_map)
                self.link_service_groups(fw_config.get('service-group', []), svc_map)
                db_sql.session.flush()

                # 4. סנכרון חוקי אבטחה (Security Rules) וקישור Many-to-Many
                self.sync_security_rules(fw_config.get('rules', []), addr_map, svc_map, app_map)

                # 5. טופולוגיית רשת
                self.sync_network_topology()

            db_sql.session.commit()
            SyncManager._last_sync_time = time.time()
            print(f"✅ Sync Success: {datetime.now().strftime('%H:%M:%S')}")
            return True
            
        except Exception as e:
            db_sql.session.rollback()
            logging.error(f"❌ Sync Error: {str(e)}", exc_info=True)
            return False
        finally:
            SyncManager._sync_lock.release()

    def _clear_database(self) -> None:
        """מנקה את כל הטבלאות הרלוונטיות לפני סנכרון חדש."""
        db_sql.session.execute(address_group_members.delete())
        db_sql.session.execute(service_group_members.delete())
        db_sql.session.execute(rule_source_map.delete())
        db_sql.session.execute(rule_dest_map.delete())
        db_sql.session.execute(rule_service_map.delete())
        db_sql.session.execute(rule_app_map.delete())
        
        db_sql.session.query(SecurityRule).delete()
        db_sql.session.query(AddressObject).delete()
        db_sql.session.query(ServiceObject).delete()
        db_sql.session.query(ApplicationObject).delete()
        db_sql.session.flush()

    def sync_address_objects(self, addr_list: list, group_list: list) -> Dict[str, int]:
        """יוצר את כל אובייקטי הכתובת והקבוצות (שלב 1)."""
        name_to_id = {}
        
        # כתובות רגילות
        for item in addr_list:
            name = item.get('name')
            if not name or name.lower() in name_to_id: continue
            
            val = (item.get('ip-netmask') or item.get('ip_netmask') or 
                   item.get('ip-range') or item.get('ip_range') or 
                   item.get('fqdn') or item.get('value') or 'any')
            if isinstance(val, list) and val: val = val[0]

            obj = AddressObject(name=name, type='host', value=str(val), is_group=False)
            db_sql.session.add(obj)
            name_to_id[name.lower()] = obj

        # אובייקטי קבוצות (ללא תוכן עדיין)
        for g in group_list:
            name = g.get('name')
            if not name or name.lower() in name_to_id: continue
            obj = AddressObject(name=name, is_group=True, type='group', value='group')
            db_sql.session.add(obj)
            name_to_id[name.lower()] = obj
            
        db_sql.session.flush()
        return {name: obj.id for name, obj in name_to_id.items()}

    def link_address_groups(self, group_list: list, addr_map: Dict[str, int]) -> None:
        """מבצע את הקישור הפיזי בין קבוצות כתובות לחברים שלהן."""
        links = []
        for g in group_list:
            parent_id = addr_map.get(g.get('name', '').lower())
            if not parent_id: continue
            
            members = g.get('static') or g.get('static_value') or []
            if isinstance(members, str): members = [members]
            
            for m_name in set(members):
                m_id = addr_map.get(m_name.lower())
                if m_id:
                    links.append({'parent_id': parent_id, 'member_id': m_id})
        
        if links:
            db_sql.session.execute(address_group_members.insert(), links)

    def sync_service_objects(self, svc_list: list, group_list: list) -> Dict[str, int]:
        """יוצר את כל אובייקטי השירות והקבוצות (שלב 1)."""
        name_to_id = {}
        for item in svc_list:
            name = item.get('name')
            if not name or name.lower() in name_to_id: continue
            
            port_val = item.get('destination-port') or item.get('destination_port') or 'any'
            obj = ServiceObject(
                name=name, protocol=item.get('protocol', 'tcp'), 
                port=str(port_val), is_group=False
            )
            db_sql.session.add(obj)
            name_to_id[name.lower()] = obj

        for g in group_list:
            name = g.get('name')
            if not name or name.lower() in name_to_id: continue
            obj = ServiceObject(name=name, is_group=True, port='group', protocol='mixed')
            db_sql.session.add(obj)
            name_to_id[name.lower()] = obj
            
        db_sql.session.flush()
        return {name: obj.id for name, obj in name_to_id.items()}

    def link_service_groups(self, group_list: list, svc_map: Dict[str, int]) -> None:
        """מבצע קישור חברים לקבוצות שירותים."""
        links = []
        for g in group_list:
            parent_id = svc_map.get(g.get('name', '').lower())
            if not parent_id: continue
            
            members = g.get('members') or g.get('static') or []
            if isinstance(members, str): members = [members]
            
            for m_name in set(members):
                m_id = svc_map.get(m_name.lower())
                if m_id:
                    links.append({'parent_id': parent_id, 'member_id': m_id})
        
        if links:
            db_sql.session.execute(service_group_members.insert(), links)

    def sync_application_objects(self, app_list: List[Dict[str, Any]]) -> Dict[str, int]:
        """סנכרון אובייקטי אפליקציה."""
        name_to_id = {}
        for item in app_list:
            name = item.get('name')
            if not name or name.lower() in name_to_id: continue
            display_val = item.get('description') or name
            obj = ApplicationObject(
                name=name, is_group=item.get('is_group', False), value=display_val
            )
            db_sql.session.add(obj)
            db_sql.session.flush()
            name_to_id[name.lower()] = obj.id
        return name_to_id

    def sync_security_rules(self, rules_list: List[Dict[str, Any]], 
                            addr_map: Dict[str, int], 
                            svc_map: Dict[str, int], 
                            app_map: Dict[str, int]) -> None:
        """סנכרון חוקי אבטחה וקישור Many-to-Many אטומי."""
        def ensure_list(val):
            if not val: return []
            return [val] if isinstance(val, str) else val

        processed_rules = set()
        for r in rules_list:
            name = r.get('name')
            if not name or name.lower() in processed_rules: continue
            processed_rules.add(name.lower())

            # חילוץ Zones
            f_raw = r.get('fromzone') or r.get('from') or ['any']
            t_raw = r.get('tozone') or r.get('to') or ['any']
            f_z = f_raw[0] if isinstance(f_raw, list) and f_raw else f_raw
            t_z = t_raw[0] if isinstance(t_raw, list) and t_raw else t_raw

            rule = SecurityRule(
                name=name, from_zone=str(f_z), to_zone=str(t_z), 
                action=r.get('action', 'allow')
            )
            db_sql.session.add(rule)
            db_sql.session.flush()

            # ביצוע קישורים ב-Bulk לכל חוק
            self._bulk_link(rule.id, r.get('source', []), addr_map, rule_source_map, 'address_id')
            self._bulk_link(rule.id, r.get('destination', []), addr_map, rule_dest_map, 'address_id')
            self._bulk_link(rule.id, r.get('service', []), svc_map, rule_service_map, 'service_id')
            self._bulk_link(rule.id, r.get('application', []), app_map, rule_app_map, 'app_id')

    def _bulk_link(self, rule_id: int, names: list, obj_map: dict, table, col_name: str) -> None:
        """פונקציית עזר להזרקת קישורים מרובים."""
        if not names: return
        if isinstance(names, str): names = [names]
        
        links = []
        for n in set(names):
            if not n or n.lower() == 'any': continue
            o_id = obj_map.get(n.lower())
            if o_id:
                links.append({'rule_id': rule_id, col_name: o_id})
        
        if links:
            db_sql.session.execute(table.insert(), links)

    def sync_network_topology(self) -> None:
        """משיכת טופולוגיית Zones (מבוסס XAPI)."""
        try:
            db_sql.session.query(NetworkInterface).delete()
            intf_res = self.fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet")
            intf_root = ET.fromstring(intf_res) if isinstance(intf_res, (str, bytes)) else intf_res
            
            iface_map = {}
            for entry in intf_root.findall(".//entry"):
                ifname = entry.get('name')
                ip_entry = entry.find(".//layer3/units/entry/ip/entry")
                if ip_entry is not None: iface_map[ifname] = ip_entry.get('name')

            zone_res = self.fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/network/zone")
            zone_root = ET.fromstring(zone_res) if isinstance(zone_res, (str, bytes)) else zone_res

            for zone in zone_root.findall(".//entry"):
                z_name = zone.get('name')
                for member in zone.findall(".//network/layer3/member"):
                    if member.text in iface_map:
                        db_sql.session.add(NetworkInterface(
                            name=member.text, subnet=iface_map[member.text], zone_name=z_name
                        ))
        except Exception as e:
            logging.error(f"⚠️ Network Topology Sync failed: {e}")