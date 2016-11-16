var reporting_password = "password";
var admin_password = "password";

use admin
db.createUser(
    {
        user: "admin", 
        pwd: (admin_password), 
        roles: [ "root" ]        
    }
)
db.auth({ user: "admin", pwd: (admin_password) })
use reporting
db.createUser(
    {
        user: "reporting", 
        pwd: (reporting_password), 
        roles: [ "dbOwner" ]
    }
)
db.auth({ user: "reporting", pwd: (reporting_password) })
db.createCollection("util_cisco_isdn")
db.createCollection("cdr_cisco_tps")
db.createCollection("util_cisco_local_tps")
db.createCollection("util_cisco_conductor_tps")
db.createCollection("cdr_cisco_isdn")
db.createCollection("util_cisco_expressway_license")
db.cdr_cisco_isdn.createIndex({"record_key":1}, {unique:true})
db.cdr_cisco_tps.createIndex({"record_key":1}, {unique:true})
db.util_cisco_conductor_tps.createIndex({"record_key":1}, {unique:true})
db.util_cisco_isdn.createIndex({"record_key":1}, {unique:true})
db.util_cisco_local_tps.createIndex({"record_key":1}, {unique:true})
db.util_cisco_expressway_license.createIndex({"record_key":1}, {unique:true})
db.util_cisco_expressway_license.createIndex({"device_serial":1})
db.util_cisco_conductor_tps.createIndex({"device_serial":1,"mcu_uuid":1})
db.cdr_cisco_tps.createIndex({"device_serial":1,"event_type":1,"disconnect_reason":1})
db.util_cisco_expressway_license.createIndex({"device_serial":1, "time_stamp":1})
db.util_cisco_conductor_tps.createIndex({"device_serial":1,"mcu_uuid":1,"time_stamp":1})
db.cdr_cisco_tps.createIndex({"device_serial":1,"time_stamp":1,"event_type":1,"disconnect_reason":1})
db.util_cisco_isdn.createIndex({"device_serial":1})
db.util_cisco_isdn.createIndex({"device_serial":1,"event_type":1,"duration":1})
db.util_cisco_isdn.createIndex({"device_serial":1,"event_type":1})
db.util_cisco_isdn.createIndex({"device_serial":1,"event_type":1,"direction":1})
db.util_cisco_isdn.createIndex({"device_serial":1,"event_type":1,"number_of_b_channels":1})
db.util_cisco_isdn.createIndex({"device_serial":1,"event_type":1,"direction":1,"duration":1})
db.util_cisco_local_tps.createIndex({"device_serial":1})
db.util_cisco_local_tps.createIndex({"device_serial":1, "time_stamp":1})
db.cdr_cisco_tps.createIndex({"endpoint_uri":1})
db.cdr_cisco_tps.createIndex({"call_id":1})
db.cdr_cisco_tps.createIndex({"conference_guid":1})
db.cdr_cisco_tps.createIndex({"conference_guid":1, "event_type":1})
db.cdr_cisco_tps.createIndex({"event_type":1})