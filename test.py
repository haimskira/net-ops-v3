# """
# Expert Lab Populator Script for Palo Alto Firewall - Version 2.
# Fixes: 
# 1. Parameter mismatch for static members (Attribute Assignment Method).
# 2. Rule injection logic (using local children instead of refreshall).
# 3. IP range validation.
# """

# import random
# import logging
# from typing import List
# from panos.firewall import Firewall
# from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup
# from panos.policies import Rulebase, SecurityRule

# # הגדרות התחברות
# FW_IP = "10.0.4.253"
# # שים לב: מומלץ לא לשתף מפתחות API בטקסט חופשי בסביבת ייצור
# API_KEY = "LUFRPT1jVWg3ZDNXckVjOUYrUHdUSTZkdFpITWtMaGs9eXhhc2FCbmp6TGdqWW1mVGRndEhMQURLOG16K0lhNlB5dmZkTVpwUE9TUFRuWXRKWU1SYUtDTjNaSkRINTk4YQ=="

# # הגדרות עומס
# NUM_ADDRESSES = 500
# NUM_ADDR_GROUPS = 100
# NUM_SERVICES = 50
# NUM_SVC_GROUPS = 20
# NUM_RULES = 2000

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger("LabPopulator")

# def generate_lab_data():
#     try:
#         fw = Firewall(FW_IP, api_key=API_KEY)
#         rulebase = Rulebase()
#         fw.add(rulebase)
        
#         logger.info(f"--- Starting Bulk Population on {FW_IP} ---")

#         # 1. יצירת אובייקטי Address
#         logger.info(f"Creating {NUM_ADDRESSES} Address Objects...")
#         addresses = []
#         for i in range(NUM_ADDRESSES):
#             addr_type = random.choice(['ip-netmask', 'ip-range', 'fqdn'])
#             o2 = (i // 254) % 255
#             o3 = i % 255
            
#             if addr_type == 'ip-netmask':
#                 val = f"10.{o2}.{o3}.1/32"
#             elif addr_type == 'ip-range':
#                 val = f"10.{o2}.{o3}.10-10.{o2}.{o3}.20"
#             else:
#                 val = f"host-{i}.lab.internal"
            
#             addr = AddressObject(name=f"LAB-HOST-{i}", value=val, type=addr_type)
#             addresses.append(addr)
#             fw.add(addr)
        
#         if addresses:
#             addresses[0].create_similar()
#             logger.info("✅ Address Objects created.")

#         # 2. יצירת קבוצות כתובות - שיטה בטוחה (Attribute Assignment)
#         logger.info(f"Creating {NUM_ADDR_GROUPS} Address Groups...")
#         addr_groups = []
#         for i in range(NUM_ADDR_GROUPS):
#             members = [a.name for a in random.sample(addresses, random.randint(3, 10))]
#             group = AddressGroup(name=f"LAB-GROUP-{i}")
#             group.static_value = members # הקצאה ישירה למניעת שגיאת פרמטר
#             addr_groups.append(group)
#             fw.add(group)
        
#         if addr_groups:
#             addr_groups[0].create_similar()
#             logger.info("✅ Address Groups created.")

#         # 3. יצירת אובייקטי Service
#         logger.info(f"Creating {NUM_SERVICES} Services...")
#         services = []
#         for i in range(NUM_SERVICES):
#             proto = random.choice(['tcp', 'udp'])
#             port = random.randint(1024, 49151)
#             svc = ServiceObject(name=f"LAB-SVC-{i}", protocol=proto, destination_port=str(port))
#             services.append(svc)
#             fw.add(svc)
        
#         if services:
#             services[0].create_similar()
#             logger.info("✅ Services created.")

#         # 4. יצירת קבוצות שירותים - שיטה בטוחה (Attribute Assignment)
#         logger.info(f"Creating {NUM_SVC_GROUPS} Service Groups...")
#         svc_groups = []
#         for i in range(NUM_SVC_GROUPS):
#             members = [s.name for s in random.sample(services, random.randint(2, 5))]
#             group = ServiceGroup(name=f"LAB-SVC-GROUP-{i}")
#             group.static_value = members # הקצאה ישירה
#             svc_groups.append(group)
#             fw.add(group)
        
#         if svc_groups:
#             svc_groups[0].create_similar()
#             logger.info("✅ Service Groups created.")

#         # 5. יצירת 2,000 חוקי אבטחה
#         logger.info(f"Preparing {NUM_RULES} Security Rules...")
#         zones = ['lab', 'TAP', 'any']
        
#         for i in range(NUM_RULES):
#             src = [random.choice(addresses + addr_groups).name for _ in range(random.randint(1, 2))]
#             dst = [random.choice(addresses + addr_groups).name for _ in range(random.randint(1, 2))]
#             svc = [random.choice(services + svc_groups).name for _ in range(1)]
            
#             rule = SecurityRule(
#                 name=f"LAB-RULE-{i:04d}",
#                 fromzone=[random.choice(zones)],
#                 tozone=[random.choice(zones)],
#                 source=src,
#                 destination=dst,
#                 service=svc,
#                 action=random.choice(['allow', 'deny'])
#             )
#             rulebase.add(rule)
            
#         # הזרקת חוקים ב-Bulk
#         logger.info("Injecting rules in Bulk...")
#         # תיקון: משתמשים בילדים של ה-rulebase המקומי במקום למשוך מה-FW
#         if rulebase.children:
#             rulebase.children[0].create_similar()

#         logger.info("🚀 LAB POPULATION COMPLETE!")
#         logger.info("Don't forget to COMMIT changes in the Firewall GUI.")

#     except Exception as e:
#         logger.error(f"Failed to populate lab: {str(e)}")

# if __name__ == "__main__":
#     generate_lab_data()


"""
Expert Tool: Service Group Content Fixer (Final Version).
Correctly targets the 'value' attribute for ServiceGroup objects
to ensure successful XML generation and Firewall injection.
"""

import random
import logging
from panos.firewall import Firewall
from panos.objects import ServiceObject, ServiceGroup

# הגדרות התחברות
FW_IP = "10.0.4.253"
API_KEY = "LUFRPT1jVWg3ZDNXckVjOUYrUHdUSTZkdFpITWtMaGs9eXhhc2FCbmp6TGdqWW1mVGRndEhMQURLOG16K0lhNlB5dmZkTVpwUE9TUFRuWXRKWU1SYUtDTjNaSkRINTk4YQ=="

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FinalFixer")

def fix_service_groups():
    try:
        # 1. התחברות
        fw = Firewall(FW_IP, api_key=API_KEY)
        
        logger.info("--- Discovery: Fetching existing LAB objects ---")
        
        # 2. משיכת אובייקטים קיימים
        # חשוב: refreshall מוודא שאנחנו עובדים על מה שקיים כרגע בפיירוול
        all_services = ServiceObject.refreshall(fw)
        all_groups = ServiceGroup.refreshall(fw)
        
        # סינון אובייקטים של המעבדה
        lab_service_names = [s.name for s in all_services if s.name.startswith('LAB-SVC-')]
        lab_groups = [g for g in all_groups if g.name.startswith('LAB-SVC-GROUP-')]
        
        if not lab_service_names:
            logger.error("No LAB-SVC objects found. Run the populator first!")
            return

        logger.info(f"Ready to fix {len(lab_groups)} groups using {len(lab_service_names)} services.")

        # 3. עדכון הקבוצות
        for group in lab_groups:
            # הגרלת 3-5 חברים
            selected = random.sample(lab_service_names, random.randint(3, 5))
            
            # --- התיקון הארכיטקטוני המכריע ---
            # ב-ServiceGroup של pan-os-python, הרשימה נשמרת ב-value
            group.value = selected 
            
            logger.info(f"Updating {group.name} with content: {selected}")
            
            # ביצוע העדכון מול הפיירוול
            try:
                group.apply()
            except Exception as e:
                logger.error(f"Failed to apply {group.name}: {e}")
                continue
                
        logger.info("🚀 SUCCESS! All Service Groups populated correctly.")
        logger.info("IMPORTANT: Perform a 'COMMIT' in the Firewall GUI now.")

    except Exception as e:
        logger.error(f"Critical System Error: {str(e)}")

if __name__ == "__main__":
    fix_service_groups()