from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from typing import Optional

db_sql = SQLAlchemy()

# --------------------------------------------------------------------------
# טבלאות עזר לקשרים (Association Tables - Many-to-Many)
# --------------------------------------------------------------------------

# קשר בין קבוצות כתובות (Address Groups) לחבריהן
address_group_members = db_sql.Table(
    'address_group_members',
    db_sql.Column('parent_id', db_sql.Integer, db_sql.ForeignKey('address_objects.id'), primary_key=True),
    db_sql.Column('member_id', db_sql.Integer, db_sql.ForeignKey('address_objects.id'), primary_key=True)
)

# קשר בין קבוצות שירותים (Service Groups) לחבריהן - התיקון המרכזי
service_group_members = db_sql.Table(
    'service_group_members',
    db_sql.Column('parent_id', db_sql.Integer, db_sql.ForeignKey('service_objects.id'), primary_key=True),
    db_sql.Column('member_id', db_sql.Integer, db_sql.ForeignKey('service_objects.id'), primary_key=True)
)

# מיפוי אובייקטי מקור לחוקי אבטחה
rule_source_map = db_sql.Table(
    'rule_source_map',
    db_sql.Column('rule_id', db_sql.Integer, db_sql.ForeignKey('security_rules.id'), primary_key=True),
    db_sql.Column('address_id', db_sql.Integer, db_sql.ForeignKey('address_objects.id'), primary_key=True)
)

# מיפוי אובייקטי יעד לחוקי אבטחה
rule_dest_map = db_sql.Table(
    'rule_dest_map',
    db_sql.Column('rule_id', db_sql.Integer, db_sql.ForeignKey('security_rules.id'), primary_key=True),
    db_sql.Column('address_id', db_sql.Integer, db_sql.ForeignKey('address_objects.id'), primary_key=True)
)

# מיפוי שירותים (פורטים) לחוקי אבטחה
rule_service_map = db_sql.Table(
    'rule_service_map',
    db_sql.Column('rule_id', db_sql.Integer, db_sql.ForeignKey('security_rules.id'), primary_key=True),
    db_sql.Column('service_id', db_sql.Integer, db_sql.ForeignKey('service_objects.id'), primary_key=True)
)

# מיפוי אפליקציות לחוקי אבטחה
rule_app_map = db_sql.Table(
    'rule_app_map',
    db_sql.Column('rule_id', db_sql.Integer, db_sql.ForeignKey('security_rules.id'), primary_key=True),
    db_sql.Column('app_id', db_sql.Integer, db_sql.ForeignKey('application_objects.id'), primary_key=True)
)

# --------------------------------------------------------------------------
# מודלים של תשתיות
# --------------------------------------------------------------------------

class AddressObject(db_sql.Model):
    __tablename__ = 'address_objects'
    id = db_sql.Column(db_sql.Integer, primary_key=True)
    name = db_sql.Column(db_sql.String(255), unique=True, index=True, nullable=False)
    type = db_sql.Column(db_sql.String(50))
    value = db_sql.Column(db_sql.String(255), index=True)
    is_group = db_sql.Column(db_sql.Boolean, default=False)
    
    members = db_sql.relationship(
        'AddressObject', 
        secondary=address_group_members,
        primaryjoin=(address_group_members.c.parent_id == id),
        secondaryjoin=(address_group_members.c.member_id == id),
        backref='member_of'
    )

class ServiceObject(db_sql.Model):
    __tablename__ = 'service_objects'
    id = db_sql.Column(db_sql.Integer, primary_key=True)
    name = db_sql.Column(db_sql.String(255), unique=True, index=True, nullable=False)
    protocol = db_sql.Column(db_sql.String(10)) 
    port = db_sql.Column(db_sql.String(255))
    is_group = db_sql.Column(db_sql.Boolean, default=False)
    
    # הוספת קשר לחברי קבוצה כדי ש-resolve_object_content יעבוד
    members = db_sql.relationship(
        'ServiceObject', 
        secondary=service_group_members,
        primaryjoin=(service_group_members.c.parent_id == id),
        secondaryjoin=(service_group_members.c.member_id == id),
        backref='member_of'
    )

class ApplicationObject(db_sql.Model):
    __tablename__ = 'application_objects'
    id = db_sql.Column(db_sql.Integer, primary_key=True)
    name = db_sql.Column(db_sql.String(255), unique=True, index=True, nullable=False)
    value = db_sql.Column(db_sql.String(255)) # שונה מ-description ל-value לסנכרון תקין
    is_group = db_sql.Column(db_sql.Boolean, default=False)

class SecurityRule(db_sql.Model):
    __tablename__ = 'security_rules'
    id = db_sql.Column(db_sql.Integer, primary_key=True)
    name = db_sql.Column(db_sql.String(255), unique=True, index=True, nullable=False)
    uuid = db_sql.Column(db_sql.String(100), unique=True)
    from_zone = db_sql.Column(db_sql.String(100), index=True)
    to_zone = db_sql.Column(db_sql.String(100), index=True)
    action = db_sql.Column(db_sql.String(20)) 
    disabled = db_sql.Column(db_sql.Boolean, default=False)
    tag_name = db_sql.Column(db_sql.String(255))
    expire_at = db_sql.Column(db_sql.DateTime, nullable=True, index=True)
    
    sources = db_sql.relationship('AddressObject', secondary=rule_source_map)
    destinations = db_sql.relationship('AddressObject', secondary=rule_dest_map)
    services = db_sql.relationship('ServiceObject', secondary=rule_service_map)
    applications = db_sql.relationship('ApplicationObject', secondary=rule_app_map)

# שאר המודלים (RuleRequest, ObjectRequest, וכו') נשארים ללא שינוי
class RuleRequest(db_sql.Model):
    __tablename__ = 'rule_requests'
    id = db_sql.Column(db_sql.Integer, primary_key=True)
    rule_name = db_sql.Column(db_sql.String(100), nullable=False)
    requested_by = db_sql.Column(db_sql.String(50), nullable=False, index=True)
    from_zone = db_sql.Column(db_sql.String(50))
    to_zone = db_sql.Column(db_sql.String(50))
    source_ip = db_sql.Column(db_sql.String(100))
    destination_ip = db_sql.Column(db_sql.String(100))
    service_port = db_sql.Column(db_sql.String(20))
    protocol = db_sql.Column(db_sql.String(10), default='tcp')
    duration_hours = db_sql.Column(db_sql.Integer, default=48)
    application = db_sql.Column(db_sql.String(50))
    tag = db_sql.Column(db_sql.String(50))
    group_tag = db_sql.Column(db_sql.String(50))
    status = db_sql.Column(db_sql.String(20), default='Pending', index=True)
    request_time = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)
    processed_by = db_sql.Column(db_sql.String(50))
    admin_notes = db_sql.Column(db_sql.Text)
    final_rule_name = db_sql.Column(db_sql.String(120))

class ObjectRequest(db_sql.Model):
    __tablename__ = 'object_requests'
    id = db_sql.Column(db_sql.Integer, primary_key=True)
    obj_type = db_sql.Column(db_sql.String(30))
    name = db_sql.Column(db_sql.String(100), nullable=False)
    value = db_sql.Column(db_sql.String(200))
    prefix = db_sql.Column(db_sql.String(10))
    protocol = db_sql.Column(db_sql.String(10))
    requested_by = db_sql.Column(db_sql.String(50))
    status = db_sql.Column(db_sql.String(20), default='Pending')
    request_time = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)
    admin_notes = db_sql.Column(db_sql.Text)

class AuditLog(db_sql.Model):
    __tablename__ = 'audit_logs'
    id = db_sql.Column(db_sql.Integer, primary_key=True)
    timestamp = db_sql.Column(db_sql.DateTime, default=datetime.utcnow, index=True)
    user = db_sql.Column(db_sql.String(50), index=True)
    action = db_sql.Column(db_sql.String(100))
    resource_type = db_sql.Column(db_sql.String(50))
    resource_name = db_sql.Column(db_sql.String(255))
    details = db_sql.Column(db_sql.Text)

class NetworkInterface(db_sql.Model):
    __tablename__ = 'network_interfaces'
    id = db_sql.Column(db_sql.Integer, primary_key=True)
    name = db_sql.Column(db_sql.String(100))
    subnet = db_sql.Column(db_sql.String(100))
    zone_name = db_sql.Column(db_sql.String(100))

class TrafficLog(db_sql.Model):
    __bind_key__ = 'logs'
    __tablename__ = 'traffic_logs'
    id = db_sql.Column(db_sql.Integer, primary_key=True)
    time = db_sql.Column(db_sql.String(20))
    source = db_sql.Column(db_sql.String(50))
    destination = db_sql.Column(db_sql.String(50))
    src_zone = db_sql.Column(db_sql.String(50))
    dst_zone = db_sql.Column(db_sql.String(50))
    app = db_sql.Column(db_sql.String(50))
    protocol = db_sql.Column(db_sql.String(20))
    dst_port = db_sql.Column(db_sql.String(20))
    action = db_sql.Column(db_sql.String(20))
    timestamp = db_sql.Column(db_sql.DateTime, default=datetime.utcnow, index=True)