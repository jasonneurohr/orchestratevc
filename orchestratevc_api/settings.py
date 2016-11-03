
schema_cdr_cisco_tps = {
    '_id':{},
    'time_stamp': {'type': 'datetime',},
    'device_serial': {'type': 'string',},
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
    'time_stamp': {'type': 'datetime',},
    'device_serial': {'type': 'string',},
    'event_type': {},
    'conference_guid': {},
    'duration': {},
}


DOMAIN = {
    'ciscoCdrTps': {
        'datasource': {
            'source': 'cdr_cisco_tps',
        },
        'resource_methods': ['GET'],
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

# Let's just use the local mongod instance. Edit as needed.

# Please note that MONGO_HOST and MONGO_PORT could very well be left
# out as they already default to a bare bones local 'mongod' instance.
MONGO_HOST = 'localhost'
MONGO_PORT = 27017

# Skip these if your db has no auth. But it really should.
#MONGO_USERNAME = '<your username>'
#MONGO_PASSWORD = '<your password>'

MONGO_DBNAME = 'reporting'

# Ends up being /api/v1/<xx>
URL_PREFIX = 'api'
API_VERSION = 'v1'