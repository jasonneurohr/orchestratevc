
schema_cdr_cisco_tps = {
    '_id':{},
    'time_stamp': {},
    'device_serial': {},
    'index': {},
    'event_type': {},
    'participant_guid': {},
    'call_id': {},
    'call_direction': {},
    'call_protocol': {},
    'endpoint_ip_address': {},
    'endpoint_display_name': {},
    'endpoint_uri': {},
    'endpoint_configured_name': {},
    'conference_guid': {},
    'time_in_conference': {},
    'disconnect_reason': {},
    'conference_name': {},
    'conference_numeric_id': {},
    'duration': {},
    'max_simultaneous_audio_only_participants': {},
    'max_simultaneous_audio_video_participants': {},
    'total_audio_only_participants': {},
    'total_audio_video_participants': {},
    'session_duration': {},
}

schema_cdr_cisco_tps_concurrent = {
    '_id':{},
    'time_stamp': {'type': 'datetime'},
    'device_serial': {'type': 'string'},
    'event_type': {'type': 'string'},
    'conference_guid': {'type': 'string'},
    'duration': {'type': 'integer'},
}


DOMAIN = {
    'ciscoCdrTps': {
        'datasource': {
            'source': 'cdr_cisco_tps',
        },
        'resource_methods': ['GET', 'POST'],
        'schema': schema_cdr_cisco_tps,
    },
    'ciscoCdrTpsConcurrent': {
        'datasource': {
            'source': 'cdr_cisco_tps',
        },
        'resource_methods': ['GET'],
        'schema': schema_cdr_cisco_tps_concurrent,
    }
}

# Update the MONGO_PASSWORD if it has been changed in the createUser.js file

MONGO_HOST = 'db'
MONGO_PORT = 27017
MONGO_USERNAME = 'reporting'
MONGO_PASSWORD = 'password'
MONGO_DBNAME = 'reporting'

# Ends up being /api/v1/<xx>
URL_PREFIX = 'api'
API_VERSION = 'v1'

SERVER_NAME = None