import requests
import xmltodict
from datetime import datetime, timedelta
from paramiko import SSHClient, AutoAddPolicy
from time import sleep
from lxml import etree
from collections import OrderedDict
from json import dumps, loads


class CiscoMS(object):
    def __init__(self, api_host="127.0.0.1", api_port="443", api_user="admin", api_pass="password"):
        self.api_host = str(api_host)
        self.api_port = str(api_port)
        self.api_user = str(api_user)
        self.api_pass = str(api_pass)

        # Resultant URLs
        self.url_api = "https://{api_host}:{api_port}/api/v1/calls".format(
            api_host=self.api_host,
            api_port=self.api_port
        )

    def get_spaces(self):
        url_secure_api = "https://" + str(self.api_host) + ":" + str(self.api_port) + "/api/v1/cospaces"
        api_session = requests.session()
        api_session.auth = str(self.api_user), str(self.api_pass)
        api_response = api_session.get(url_secure_api, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response.text)
        total_spaces = int(xml_api_response['coSpaces']['@total'])
        space_dict = {}

        if total_spaces == 0:  # No spaces
            return

        if total_spaces == 1:  # Only 1 space
            space_id = xml_api_response['coSpaces']['coSpace']['@id']
            space_name = xml_api_response['coSpaces']['coSpace']['name']
            space_dict[space_id] = space_name
            return space_dict

        if total_spaces > 1:  # More then 1 space
            offset = 0
            while offset != total_spaces:
                url_secure_api = "https://" + str(self.api_host) + ":" + str(self.api_port) + \
                                 "/api/v1/cospaces?offset=" + str(offset) + "&limit=10"
                api_response = api_session.get(url_secure_api, verify=False, timeout=10)
                xml_api_response = xmltodict.parse(api_response.text)

                for space in xml_api_response['coSpaces']['coSpace']:  # Get the initial response items
                    offset += 1  # Increment the offset for each record return
                    space_id = space['@id']
                    space_name = space['name']
                    space_dict[space_id] = space_name
            return space_dict
        api_session.close()

    def get_space_callprofile(self, space_id):
        url_secure_api = "https://" + str(self.api_host) + ":" + str(self.api_port) + "/api/v1/cospaces" + space_id
        api_session = requests.session()
        api_session.auth = str(self.api_user), str(self.api_pass)
        api_response = api_session.get(url_secure_api, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response.text)

        try:
            callprofile_id = xml_api_response['coSpace']['callProfile']
            has_callprofile = 1
        except:
            has_callprofile = 0
            pass

        if has_callprofile == 1:
            return callprofile_id
        else:
            return

    def get_space_accessmethods(self, space_id):
        accessmethod_ids = []
        url_secure_api_accessmethods = \
            "https://" + str(self.api_host) + ":" + str(self.api_port) + "/api/v1/cospaces/" \
                                       + space_id + "/accessmethods/"
        api_session = requests.session()
        api_session.auth = str(self.api_user), str(self.api_pass)
        api_response_accessmethods = api_session.get(url_secure_api_accessmethods, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response_accessmethods.text)

        total_accessmethods = int(xml_api_response['accessMethods']['@total'])

        if total_accessmethods == 0:  # NO ACCESS METHODS.... RETURN
            return
        if total_accessmethods == 1:
            accessmethod_id = xml_api_response['accessMethods']['accessMethod']['@id']
            return accessmethod_id
        if total_accessmethods > 1:
            for accessmethod in xml_api_response['accessMethods']['accessMethod']:
                accessmethod_ids.append(accessmethod['@id'])
            return accessmethod_ids

    def get_space_calllegprofiles(self, space_id, accessmethod_id):
        url_secure_api = "https://" + str(self.api_host) + ":" + str(self.api_port) + "/api/v1/cospaces"
        api_session = requests.session()
        api_session.auth = str(self.api_user), str(self.api_pass)
        api_response = api_session.get(url_secure_api, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response.text)
        try:
            calllegprofile_id = xml_api_response['accessMethod']['callLegProfile']
            return calllegprofile_id
        except:
            return

    def get_total_conferences(self):
        api_session = requests.session()
        api_session.auth = self.api_user, self.api_pass
        api_response_conferences = api_session.get(self.url_api, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response_conferences.text)

        try:
            total_conferences = xml_api_response['calls']['@total']
        except:
            return 0

        return int(total_conferences)

    def set_all_calllegprofile_properties(self, properties={}):
        url_secure_api = "https://" + str(self.api_host) + ":" + str(self.api_port) + "/api/v1/calllegprofiles"
        api_session = requests.session()
        api_session.auth = str(self.api_user), str(self.api_pass)
        api_response = api_session.get(url_secure_api, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response.text)
        total_profiles = int(xml_api_response['callLegProfiles']['@total'])

        if total_profiles == 0:  # No profiles
            return

        if total_profiles == 1:  # Only 1 profile
            calllegprofile_id = xml_api_response['callLegProfiles']['callLegProfile']['@id']
            url_secure_api = "https://" + str(self.api_host) + ":" + str(self.api_port) + \
                             "/api/v1/calllegprofiles/" + calllegprofile_id
            api_response = api_session.put(url_secure_api, data=properties, verify=False, timeout=10)
            return

        offset = 0
        while offset != total_profiles:
            url_secure_api = "https://" + str(self.api_host) + ":" + str(self.api_port) + \
                             "/api/v1/calllegprofiles?offset=" + str(offset) + "&limit=10"
            api_response = api_session.get(url_secure_api, verify=False, timeout=10)
            xml_api_response = xmltodict.parse(api_response.text)

            for calllegprofile in xml_api_response['callLegProfiles']['callLegProfile']:
                offset += 1
                calllegprofile_id = str(calllegprofile['@id'])
                url_secure_api = "https://" + str(self.api_host) + ":" + str(self.api_port) + \
                                 "/api/v1/calllegprofiles/" + calllegprofile_id
                api_response = api_session.put(url_secure_api, data=properties, verify=False, timeout=10)
                print(api_response.text)
        return

    def del_spaces_and_artifacts(self, filter=[]):
        url_secure_api = "https://" + str(self.api_host) + ":" + str(self.api_port) + "/api/v1/cospaces"
        api_session = requests.session()
        api_session.auth = str(self.api_user), str(self.api_pass)
        api_response = api_session.get(url_secure_api, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response.text)
        total_spaces = int(xml_api_response['coSpaces']['@total'])

        if total_spaces == 0:  # No spaces
            return

        if total_spaces == 1:
            space_id = str(xml_api_response['coSpaces']['coSpace']['@id'])
            callprofile_id = self.get_space_callprofile(space_id)

            # Check if the space ID is in the filter list, if True return
            if space_id in filter:
                return

            if callprofile_id is not None:  # Space has a profile which will be deleted
                url_secure_api_callprofile = \
                    "https://" + str(self.api_host) + ":" + str(self.api_port) + "/api/v1/callprofiles/" + callprofile_id
                api_session.delete(url_secure_api_callprofile, verify=False, timeout=10)

            accessmethod_ids = self.get_space_accessmethods(space_id)

            if type(accessmethod_ids) == str:  # Only 1 accessmethod
                calllegprofile_id = self.get_space_calllegprofiles(space_id, accessmethod_ids)
                if callprofile_id is not None:
                    url_secure_api_calllegprofile = \
                        "https://" + str(self.api_host) + ":" + str(self.api_port) + "/api/v1/calllegprofiles/" + \
                        calllegprofile_id
                    api_session.delete(url_secure_api_calllegprofile, verify=False, timeout=10)
            if type(accessmethod_ids) == list:  # Multiple access methods
                for accessmethod_id in accessmethod_ids:
                    calllegprofile_id = self.get_space_calllegprofiles(space_id,accessmethod_id)
                    if calllegprofile_id is not None:
                        url_secure_api_calllegprofile = \
                            "https://" + str(self.api_host) + ":" + str(self.api_port) + "/api/v1/calllegprofiles/" + \
                            calllegprofile_id
                        api_session.delete(url_secure_api_calllegprofile, verify=False, timeout=10)

            # Finally delete the space (and subsequently the access methods)
            url_secure_api_space = "https://" + str(self.api_host) + ":" + str(self.api_port) + "/api/v1/cospaces/" + space_id
            api_session.delete(url_secure_api_space, verify=False, timeout=10)

        if total_spaces > 1:
            for space in xml_api_response['coSpaces']['coSpace']:
                space_id = str(space['@id'])
                callprofile_id = self.get_space_callprofile(space_id)

                # Check if the space ID is in the filter list, if True pass
                if space_id in filter:
                    pass
                else:
                    if callprofile_id is not None:  # Space has a profile which will be deleted
                        url_secure_api_callprofile = \
                            "https://" + str(self.api_host) + ":" + str(
                                self.api_port) + "/api/v1/callprofiles/" + callprofile_id
                        api_session.delete(url_secure_api_callprofile, verify=False, timeout=10)

                    accessmethod_ids = self.get_space_accessmethods(space_id)

                    if type(accessmethod_ids) == str:  # Only 1 accessmethod
                        calllegprofile_id = self.get_space_calllegprofiles(space_id, accessmethod_id)
                        if callprofile_id is not None:
                            url_secure_api_calllegprofile = \
                                "https://" + str(self.api_host) + ":" + str(self.api_port) + \
                                "/api/v1/calllegprofiles/" +  calllegprofile_id
                            api_session.delete(url_secure_api_calllegprofile, verify=False, timeout=10)
                    if type(accessmethod_ids) == list:  # Multiple access methods
                        for accessmethod_id in accessmethod_ids:
                            calllegprofile_id = self.get_space_calllegprofiles(space_id, accessmethod_id)
                            if calllegprofile_id is not None:
                                url_secure_api_calllegprofile = \
                                    "https://" + str(self.api_host) + ":" + str(
                                        self.api_port) + "/api/v1/calllegprofiles/" + \
                                    calllegprofile_id
                                api_session.delete(url_secure_api_calllegprofile, verify=False, timeout=10)

                    # Finally delete the space (and subsequently the access methods)
                    url_secure_api_space = "https://" + str(self.api_host) + ":" + str(
                        self.api_port) + "/api/v1/cospaces/" + space_id
                    api_session.delete(url_secure_api_space, verify=False, timeout=10)


class CiscoMSESupervisor(object):
    def __init__(self, api_host="127.0.0.1", api_user="admin", api_pass="password", secure_conn=True):
        self.api_host = str(api_host)
        self.api_user = str(api_user)
        self.api_pass = str(api_pass)
        self.secure_conn = secure_conn

        # Resultant URLs
        self.url_auth_secure = "https://" + str(self.api_host) + "/login_change.html"
        self.url_auth = "http://" + str(self.api_host) + "/login_change.html"
        if self.secure_conn is True:
            self.url_api = "https://" + str(self.api_host) + "/RPC2"
        elif self.secure_conn is False:
            self.url_api = "http://" + str(self.api_host) + "/RPC2"

    def export_config(self):
        """
        Connects to the web interface of the MSE Supervisor, and pulls the configuration.xml file which it returns.
        :return:
        """

        # Post credentials, and the requested page to the login form
        host_session = requests.session()
        post_data = {'user_name': self.api_user, 'password': self.api_pass, 'requested_page': 'configuration.xml'}
        try:
            host_response = host_session.post(self.url_auth_secure, data=post_data, verify=False, timeout=10)
        except (requests.Timeout, requests.ConnectionError):
            host_response = host_session.post(self.url_auth, data=post_data, verify=False, timeout=10)

        return host_response.text

    def get_blade_status(self):  # Todo
        post_req = "<methodCall><methodName>chassis.blades.query</methodName><params><param><value><struct><member>" \
                   "<name>authenticationPassword</name><value><string>{api_pass}</string></value></member><member>" \
                   "<name>authenticationUser</name><value><string>{api_user}</string></value></member></struct></value><" \
                   "/param></params></methodCall>".format(
            api_pass=self.api_pass,
            api_user=self.api_user
        )

        session = requests.session()
        host_response = session.post(self.url_api, data=post_req, verify=False, timeout=10)

        xml_to_dict = xmltodict.parse(host_response.text)
        base_xml_path = xml_to_dict["methodResponse"]["params"]["param"]["value"]["struct"]["member"]["value"] \
            ["array"]["data"]["value"]

        blades = []

        for blade in base_xml_path:
            blade_properties = OrderedDict()
            for blade_keys in blade["struct"]["member"]:
                if blade_keys['name'] == 'slot':
                    blade_properties['slot'] = blade_keys["value"]["int"]
                if blade_keys['name'] == 'type':
                    blade_properties['blade_type'] = blade_keys["value"]["string"]
                if blade_keys['name'] == 'status':
                    blade_properties['blade_status'] = blade_keys["value"]["string"]
                if blade_keys['name'] == 'softwareVersion':
                    blade_properties['blade_version'] = blade_keys["value"]["string"]
                if blade_keys['name'] == 'portA':
                    blade_properties['blade_ip'] = blade_keys["value"]["string"]

            blades.append(blade_properties)

        return blades

    def get_fantry_status(self):  # Todo
        # chassis.fantrays.query
        return

    def get_chassis_health(self):  # Todo
        # device.health.query
        return

    def get_chassis_info(self):  # Todo
        # device.query
        return


class CiscoTPS(object):
    def __init__(self, api_host="127.0.0.1", api_user="admin", api_pass="password", secure_conn=True):
        self.api_host = str(api_host)
        self.api_user = str(api_user)
        self.api_pass = str(api_pass)
        self.secure_conn = secure_conn

        # Resultant URLs
        if self.secure_conn is True:
            self.url_api = "https://" + str(self.api_host) + "/RPC2"
            self.url_sys = "https://" + str(self.api_host) + "/system.xml"
            self.url_conf = "https://" + str(self.api_host) + "/configuration.xml"
            self.url_auth = "https://" + str(self.api_host) + "/login_change.html"
            self.url_auth = "http://" + str(self.api_host) + "/login_change.html"
            self.url_logout = "https://" + str(self.api_host) + "/logout.html"
        elif self.secure_conn is False:
            self.url_api = "http://" + str(self.api_host) + "/RPC2"
            self.url_sys = "http://" + str(self.api_host) + "/system.xml"
            self.url_conf = "http://" + str(self.api_host) + "/configuration.xml"
            self.url_auth = "http://" + str(self.api_host) + "/login_change.html"
            self.url_logout = "http://" + str(self.api_host) + "/logout.html"

        # TPS object properties
        self.serial = None
        self.sys_name = None
        self.utf_offset = None

        # Used for CDR processing
        self.cdr_next_index = 0
        self.cdr_start_index = 0
        self.cdr_events_remaining = 0
        self.cdr_last_read_index = 0
        self.cdr_jar = []

        # Call get_properties method to initialise the TPS object properties
        self.get_properties()

    def export_config(self):
        """
        Connects to the web interface of the TPS, and pulls the configuration.xml file which it returns.
        :return:
        """

        # Post credentials, and the requested page to the login form
        host_session = requests.session()
        post_data = {'user_name': self.api_user, 'password': self.api_pass, 'requested_page': 'configuration.xml'}
        try:
            host_response = host_session.post(self.url_auth, data=post_data, verify=False, timeout=10)
        except (requests.Timeout, requests.ConnectionError) as e:
            return

        return host_response.text

    def get_properties(self):
        """
        Gets various TPS properties and returns them as JSON
        :return:
        """
        auth_payload = {'user_name': self.api_user, 'password': self.api_pass}
        session = requests.session()

        post_data = """\
        <methodCall>
            <methodName>system.info</methodName>
                <params>
                    <param>
                        <value>
                            <struct>
                                <member>
                                    <name>authenticationPassword</name>
                                    <value><string>%s</string></value>
                                </member>
                                <member>
                                    <name>authenticationUser</name>
                                    <value><string>%s</string></value>
                                </member>
                            </struct>
                        </value>
                    </param>
                </params>
        </methodCall>
        """ % (self.api_pass, self.api_user)

        try:
            r = session.post(self.url_api, data=post_data, verify=False, timeout=10)
        except Exception as e:
            return e

        xml_to_dict = xmltodict.parse(r.text)
        base_xml_path = xml_to_dict["methodResponse"]["params"]["param"]["value"]["struct"]["member"]

        dictConvertedToJson = dumps(xml_to_dict, indent=4, separators=(',', ': '))
        jsonConvertedToCleanDict = loads(dictConvertedToJson)

        try:
            r = session.get(self.url_sys, verify=False, timeout=10)
        except Exception as e:
            return e

        system_xml_to_dict = xmltodict.parse(r.text)
        platform = system_xml_to_dict["system"]["platform"]
        serial = system_xml_to_dict["system"]["serial"]
        software_version = system_xml_to_dict["system"]["softwareVersion"]
        build_version = system_xml_to_dict["system"]["buildVersion"]
        system_name = system_xml_to_dict["system"]["hostName"]
        ip_address = system_xml_to_dict["system"]["ipAddress"]
        mac_address = system_xml_to_dict["system"]["macAddress"]
        total_video_ports = system_xml_to_dict["system"]["totalVideoPorts"]
        total_content_ports = system_xml_to_dict["system"]["totalContentPorts"]
        total_audio_ports = system_xml_to_dict["system"]["totalAudioOnlyPorts"]
        cluster_type = system_xml_to_dict["system"]["clusterType"]
        uptime = system_xml_to_dict["system"]["uptimeSeconds"]

        try:
            session.post(self.url_auth, data=auth_payload, verify=False, timeout=10)
            r = session.get(self.url_conf, verify=False, timeout=10)
            session.get(self.url_logout, verify=False, timeout=10)
        except Exception as e:
            return e

        conf_xml_to_dict = xmltodict.parse(r.text)
        utc_offset = conf_xml_to_dict['configuration']['settings']['ntp']['@utc_offset']

        # WHEN CONDUCTOR IS INVOLVED THIS INTRODUCES SOME EXTRA FIELDS IN THE RESPONSE
        # WHICH NEED TO BE ACCOUNTED FOR
        if base_xml_path[4]["name"] == "depHash":
            if str(build_version) == "13.1(1.95)":
                x = 0
            tpsVideoPortsFree = base_xml_path[10]["value"]["int"]
            tpsInUseVideoPorts = int(total_video_ports) - int(tpsVideoPortsFree)
            tpsAudioPortsFree = base_xml_path[12]["value"]["int"]
            tpsInUseAudioPorts = int(total_audio_ports) - int(tpsAudioPortsFree)
            tpsContentPortsFree = base_xml_path[14]["value"]["int"]
            tpsInUseContentPorts = int(total_content_ports) - int(tpsContentPortsFree)
            tpsMaxConferenceSizeVideo = base_xml_path[15]["value"]["int"]
            tpsMaxConferenceSizeAudio = base_xml_path[17]["value"]["int"]
            tpsNumControlledServers = base_xml_path[18]["value"]["int"]
            tpsOperationMode = base_xml_path[19]["value"]["string"]
            if tpsOperationMode == "slave":
                tpsLicenseMode = None

            else:
                tpsLicenseMode = base_xml_path[20]["value"]["string"]

        # THESE MAPPINGS WORK FOR STANDALONE
        else:
            if str(build_version) == "13.1(1.95)":
                x = -1
            else:
                x = 0
            tpsVideoPortsFree = base_xml_path[9 + x]["value"]["int"]
            tpsInUseVideoPorts = int(total_video_ports) - int(tpsVideoPortsFree)
            tpsAudioPortsFree = base_xml_path[11 + x]["value"]["int"]
            tpsInUseAudioPorts = int(total_audio_ports) - int(tpsAudioPortsFree)
            tpsContentPortsFree = base_xml_path[13 + x]["value"]["int"]
            tpsInUseContentPorts = int(total_content_ports) - int(tpsContentPortsFree)
            tpsMaxConferenceSizeVideo = base_xml_path[14 + x]["value"]["int"]
            tpsMaxConferenceSizeAudio = base_xml_path[16 + x]["value"]["int"]
            tpsNumControlledServers = base_xml_path[17 + x]["value"]["int"]
            tpsOperationMode = base_xml_path[18 + x]["value"]["string"]
            if tpsOperationMode == "slave":
                tpsLicenseMode = None

            else:
                tpsLicenseMode = base_xml_path[19 + x]["value"]["string"]

        propertyDict = {"tpsSoftwareVersion": software_version,
                        "tpsSystemName": system_name,
                        "tpsUptime": uptime,
                        "tpsSerial": serial,
                        "tpsTotalVideoPorts": total_video_ports,
                        "tpsVideoPortsFree": tpsVideoPortsFree,
                        "tpsInUseVideoPorts": tpsInUseVideoPorts,
                        "tpsTotalAudioPorts": total_audio_ports,
                        "tpsAudioPortsFree": tpsAudioPortsFree,
                        "tpsInUseAudioPorts": tpsInUseAudioPorts,
                        "tpsTotalContentPorts": total_content_ports,
                        "tpsContentPortsFree": tpsContentPortsFree,
                        "tpsInUseContentPorts": tpsInUseContentPorts,
                        "tpsMaxConferenceSizeVideo": tpsMaxConferenceSizeVideo,
                        "tpsMaxConferenceSizeAudio": tpsMaxConferenceSizeAudio,
                        "tpsNumControlledServers": tpsNumControlledServers,
                        "tpsOperationMode": tpsOperationMode,
                        "tpsLicenseMode": tpsLicenseMode,
                        "tpsClusterType": cluster_type,
                        "tpsPlatform": platform,
                        "utc_offset": utc_offset
                        }

        self.serial = serial
        self.sys_name = system_name
        self.utf_offset = utc_offset
        return (propertyDict)

    def get_util(self):
        """
        Calls the get_properties method and uses the results to return utilisation data in JSON
        :return:
        """
        results = self.get_properties()
        data_dict = OrderedDict()
        data_dict['time_stamp'] = str(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S'))
        data_dict['device_serial'] = results["tpsSerial"]
        data_dict['device_name'] = results["tpsSystemName"]
        data_dict['total_video_ports'] = results["tpsTotalVideoPorts"]
        data_dict['used_video_ports'] = results["tpsInUseVideoPorts"]
        data_dict['total_audio_ports'] = results["tpsTotalAudioPorts"]
        data_dict['used_audio_ports'] = results["tpsInUseAudioPorts"]
        data_dict['total_content_ports'] = results["tpsTotalContentPorts"]
        data_dict['used_content_ports'] = results["tpsInUseContentPorts"]
        data_dict['license_mode'] = results["tpsLicenseMode"]
        data_dict['record_type'] = 'util_cisco_local_tps'
        data_dict['record_key'] = str(data_dict['device_serial']) + \
                                  "_" + str(datetime.utcnow().strftime('%Y%m%d%H%M%S'))

        return dumps(data_dict)

    def get_cdrs(self):
        td = timedelta(hours=int(self.utf_offset))

        post_data = """\
            <methodCall>
                <methodName>cdrlog.enumerate</methodName>
                <params>
                    <param>
                        <value>
                            <struct>
                                <member>
                                    <name>authenticationPassword</name>
                                    <value><string>%s</string></value>
                                </member>
                                <member>
                                    <name>authenticationUser</name>
                                    <value><string>%s</string></value>
                                </member>
                                <member>
                                    <name>index</name>
                                    <value><int>%s</int></value>
                                </member>
                            </struct>
                        </value>
                    </param>
                </params>
            </methodCall>
            """ % (self.api_pass, self.api_user, self.cdr_last_read_index)

        session = requests.session()

        try:
            r = session.post(self.url_api, post_data, verify=False, timeout=10)
        except (requests.Timeout, requests.ConnectionError):
            r = session.post()

        xml_to_dict = xmltodict.parse(r.text)
        base_xml_path = xml_to_dict['methodResponse']['params']\
            ['param']['value']['struct']['member'][0]['value']['array']['data']['value']

        self.cdr_start_index = xml_to_dict['methodResponse']['params'] \
            ['param']['value']['struct']['member'][1]['value']['int']
        self.cdr_events_remaining = xml_to_dict['methodResponse']['params'] \
            ['param']['value']['struct']['member'][2]['value']['boolean']

        for cdr_dict in base_xml_path:
            base_cdr_path = cdr_dict['struct']['member'][3]

            stream_list = []  # Used in participantMediaSummary CDR type
            uri_list = []  # Used in conferenceStarted CDR type

            try:
                index_id = cdr_dict['struct']['member'][0]['value']['int']
            except Exception as e:
                # Can't get the index lets check if this record had 0 events remaining
                # if it does we can safetly assume that this is ok. otherwise we have an error
                if self.cdr_events_remaining == "0":
                    # Nothing left
                    return
                elif self.cdr_events_remaining == "1":
                    # Can't find event index
                    return

            # Get the CDR timestamp, deduct the TZ, reformat
            timestamp = cdr_dict['struct']['member'][1]['value']['dateTime.iso8601']
            timestamp = datetime.strptime(timestamp, "%Y%m%dT%H:%M:%S") - td
            timestamp = datetime.strptime(str(timestamp), "%Y-%m-%d %H:%M:%S").strftime('%Y-%m-%dT%H:%M:%S')
            event_type = cdr_dict['struct']['member'][2]['value']['string']

            # Create a unique key for the record
            record_key_timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S").strftime('%Y%m%d%H%M%S')
            record_key = self.serial + "_" + str(index_id) + "_" + str(record_key_timestamp)

            # CDR type conferenceStarted
            try:
                if event_type == "conferenceStarted":
                    conference_guid = base_cdr_path['value']['struct']['member'][0]['value']['string']
                    conference_name = base_cdr_path['value']['struct']['member'][1]['value']['string']
                    conference_numeric_id = base_cdr_path['value']['struct']['member'][2]['value']['string']

                    if type(base_cdr_path['value']['struct']['member'][3]['value']['array'] \
                        ['data']['value']) == list:

                        uri_dict = OrderedDict()

                        for item in base_cdr_path['value']['struct']['member'][3]['value']['array'] \
                        ['data']['value']:
                            conference_uri = item['struct']['member'][0]['value']['string']
                            pin_protected = item['struct']['member'][1]['value']['string']

                            uri_dict['uri'] = conference_uri
                            uri_dict['pin_protected'] = pin_protected
                            uri_list.append(uri_dict)

                    if type(base_cdr_path['value']['struct']['member'][3]['value']['array'] \
                        ['data']['value']) == dict:
                        uri_string = base_cdr_path['value']['struct']['member'][3]['value']['array'] \
                        ['data']['value']['struct']['member'][0]['value']['string']
                        pin_protected = base_cdr_path['value']['struct']['member'][3]['value']['array'] \
                        ['data']['value']['struct']['member'][1]['value']['string']

                        uri_dict['uri'] = uri_string
                        uri_dict['pin_protected'] = pin_protected
                        uri_list.append(uri_dict)

                    data_dict = OrderedDict()
                    data_dict['time_stamp'] = timestamp
                    data_dict['device_serial'] = self.serial
                    data_dict['device_name'] = self.sys_name
                    data_dict['index'] = index_id
                    data_dict['event_type'] = event_type
                    data_dict['conference_guid'] = conference_guid
                    data_dict['conference_name'] = conference_name
                    data_dict['conference_numeric_id'] = conference_numeric_id
                    data_dict['conference_uri'] = uri_list
                    data_dict['record_type'] = 'cdr_cisco_tps'
                    data_dict['record_key'] = record_key

                    record_string = dumps(data_dict)

            except Exception as e:
                return e
            # End CDR type conferenceStarted

            # CDR type conferenceFinished
            try:
                if event_type == "conferenceFinished":
                    conference_guid = base_cdr_path['value']['struct']['member'][0]['value']['string']
                    max_simultaneous_audio_video_participants = base_cdr_path['value']['struct']['member'] \
                        [1]['value']['int']
                    max_simultaneous_audio_only_participants = base_cdr_path['value']['struct']['member'] \
                        [2]['value']['int']
                    total_audio_video_participants = base_cdr_path['value']['struct']['member'] \
                        [3]['value']['int']
                    total_audio_only_participants = base_cdr_path['value']['struct']['member'] \
                        [4]['value']['int']
                    duration = base_cdr_path['value']['struct']['member'][5]['value']['int']

                    data_dict = OrderedDict()
                    data_dict['time_stamp'] = timestamp
                    data_dict['device_serial'] = self.serial
                    data_dict['device_name'] = self.sys_name
                    data_dict['index'] = index_id
                    data_dict['event_type'] = event_type
                    data_dict['conference_guid'] = conference_guid
                    data_dict['max_simultaneous_audio_video_participants'] = max_simultaneous_audio_video_participants
                    data_dict['max_simultaneous_audio_only_participants'] = max_simultaneous_audio_only_participants
                    data_dict['total_audio_video_participants'] = total_audio_video_participants
                    data_dict['total_audio_only_participants'] = total_audio_only_participants
                    data_dict['duration'] = duration
                    data_dict['record_type'] = 'cdr_cisco_tps'
                    data_dict['record_key'] = record_key

                    record_string = dumps(data_dict)

            except Exception as e:
                return e
            # End CDR type conferenceFinished

            # CDR Type conferenceActive
            try:
                if event_type == "conferenceActive":
                    conference_guid = base_cdr_path['value']['struct']['member']['value']['string']

                    data_dict = OrderedDict()
                    data_dict['time_stamp'] = timestamp
                    data_dict['device_serial'] = self.serial
                    data_dict['device_name'] = self.sys_name
                    data_dict['index'] = index_id
                    data_dict['event_type'] = event_type
                    data_dict['conference_guid'] = conference_guid
                    data_dict['record_type'] = 'cdr_cisco_tps'
                    data_dict['record_key'] = record_key

                    record_string = dumps(data_dict)

            except Exception as e:
                return e
            # End CDR type conferenceActive

            # CDR type participantJoined
            try:
                if event_type == "participantJoined":
                    conference_guid = base_cdr_path['value']['struct']['member'][0]['value']['string']
                    participant_guid = base_cdr_path['value']['struct']['member'][1]['value']['string']
                    call_id = base_cdr_path['value']['struct']['member'][2]['value']['string']

                    data_dict = OrderedDict()
                    data_dict['time_stamp'] = timestamp
                    data_dict['device_serial'] = self.serial
                    data_dict['device_name'] = self.sys_name
                    data_dict['index'] = index_id
                    data_dict['event_type'] = event_type
                    data_dict['conference_guid'] = conference_guid
                    data_dict['participant_guid'] = participant_guid
                    data_dict['call_id'] = call_id
                    data_dict['record_type'] = 'cdr_cisco_tps'
                    data_dict['record_key'] = record_key

                    record_string = dumps(data_dict)

            except Exception as e:
                return e
            # End CDR TYPE participantJoined

            # CDR type participantConnected
            try:
                if event_type == "participantConnected":
                    participant_guid = base_cdr_path['value']['struct']['member'][0]['value']['string']
                    call_id = base_cdr_path['value']['struct']['member'][1]['value']['string']
                    call_direction = base_cdr_path['value']['struct']['member'][2]['value']['string']
                    call_protocol = base_cdr_path['value']['struct']['member'][3]['value']['string']
                    endpoint_ip_address = base_cdr_path['value']['struct']['member'][4]['value']['string']
                    endpoint_display_name = base_cdr_path['value']['struct']['member'][5]['value']['string']
                    endpoint_uri = base_cdr_path['value']['struct']['member'][6]['value']['string']
                    endpoint_configured_name = base_cdr_path['value']['struct']['member'][7]['value']['string']

                    data_dict = OrderedDict()
                    data_dict['time_stamp'] = timestamp
                    data_dict['device_serial'] = self.serial
                    data_dict['device_name'] = self.sys_name
                    data_dict['index'] = index_id
                    data_dict['event_type'] = event_type
                    data_dict['participant_guid'] = participant_guid
                    data_dict['call_id'] = call_id
                    data_dict['call_direction'] = call_direction
                    data_dict['call_protocol'] = call_protocol
                    data_dict['endpoint_ip_address'] = endpoint_ip_address
                    data_dict['endpoint_display_name'] = endpoint_display_name
                    data_dict['endpoint_uri'] = endpoint_uri
                    data_dict['endpoint_configured_name'] = endpoint_configured_name
                    data_dict['record_type'] = 'cdr_cisco_tps'
                    data_dict['record_key'] = record_key

                    record_string = dumps(data_dict)

            except Exception as e:
                return e
            # End CDR type participantConnected

            # CDR type participantLeft
            try:
                if event_type == "participantLeft":
                    conference_guid = base_cdr_path['value']['struct']['member'][0]['value']['string']
                    participant_guid = base_cdr_path['value']['struct']['member'][1]['value']['string']
                    call_id = base_cdr_path['value']['struct']['member'][2]['value']['string']
                    time_in_conference = base_cdr_path['value']['struct']['member'][3]['value']['int']

                    data_dict = OrderedDict()
                    data_dict['time_stamp'] = timestamp
                    data_dict['device_serial'] = self.serial
                    data_dict['device_name'] = self.sys_name
                    data_dict['index'] = index_id
                    data_dict['event_type'] = event_type
                    data_dict['conference_guid'] = conference_guid
                    data_dict['participant_guid'] = participant_guid
                    data_dict['call_id'] = call_id
                    data_dict['time_in_conference'] = time_in_conference
                    data_dict['record_type'] = 'cdr_cisco_tps'
                    data_dict['record_key'] = record_key

                    record_string = dumps(data_dict)

            except Exception as e:
                return e
            # End CDR type participantLeft

            # CDR type participantDisconnected
            try:
                if event_type == "participantDisconnected":
                    participant_guid = base_cdr_path['value']['struct']['member'][0]['value']['string']
                    call_id = base_cdr_path['value']['struct']['member'][1]['value']['string']
                    disconnect_reason = base_cdr_path['value']['struct']['member'][2]['value']['string']

                    if base_cdr_path['value']['struct']['member'][3]['value']['string']:
                        call_direction = base_cdr_path['value']['struct']['member'][3]['value']['string']
                    else:
                        call_direction = ""
                    if base_cdr_path['value']['struct']['member'][4]['value']['string']:
                        call_protocol = base_cdr_path['value']['struct']['member'][4]['value']['string']
                    else:
                        call_protocol = ""
                    if base_cdr_path['value']['struct']['member'][5]['value']['string']:
                        endpoint_ip_address = base_cdr_path['value']['struct']['member'][5]['value']['string']
                    else:
                        endpoint_ip_address = ""
                    if base_cdr_path['value']['struct']['member'][6]['value']['string']:
                        endpoint_display_name = base_cdr_path['value']['struct']['member'][6]['value']['string']
                    else:
                        endpoint_display_name = ""
                    if base_cdr_path['value']['struct']['member'][7]['value']['string']:
                        endpoint_uri = base_cdr_path['value']['struct']['member'][7]['value']['string']
                    else:
                        endpoint_uri = ""
                    if base_cdr_path['value']['struct']['member'][8]['value']['string']:
                        endpoint_configured_name = base_cdr_path['value']['struct']['member'][8]['value']['string']
                    else:
                        endpoint_configured_name = ""

                    data_dict = OrderedDict()
                    data_dict['time_stamp'] = timestamp
                    data_dict['device_serial'] = self.serial
                    data_dict['device_name'] = self.sys_name
                    data_dict['index'] = index_id
                    data_dict['event_type'] = event_type
                    data_dict['participant_guid'] = participant_guid
                    data_dict['call_id'] = call_id
                    data_dict['disconnect_reason'] = disconnect_reason
                    data_dict['call_direction'] = call_direction
                    data_dict['call_protocol'] = call_protocol
                    data_dict['endpoint_ip_address'] = endpoint_ip_address
                    data_dict['endpoint_display_name'] = endpoint_display_name
                    data_dict['endpoint_uri'] = endpoint_uri
                    data_dict['endpoint_configured_name'] = endpoint_configured_name
                    data_dict['record_type'] = 'cdr_cisco_tps'
                    data_dict['record_key'] = record_key

                    record_string = dumps(data_dict)

            except Exception as e:
                return e
            # END CDR type participantDisconnected

            # CDR type conferenceInactive
            try:
                if event_type == "conferenceInactive":
                    conference_guid = base_cdr_path['value']['struct']['member'][0]['value']['string']
                    max_simultaneous_audio_video_participants = base_cdr_path['value']['struct']['member'] \
                        [1]['value']['int']
                    max_simultaneous_audio_only_participants = base_cdr_path['value']['struct']['member'] \
                        [2]['value']['int']
                    total_audio_video_participants = base_cdr_path['value']['struct']['member'] \
                        [3]['value']['int']
                    total_audio_only_participants = base_cdr_path['value']['struct']['member'] \
                        [4]['value']['int']
                    session_duration = base_cdr_path['value']['struct']['member'] \
                        [5]['value']['int']

                    data_dict = OrderedDict()
                    data_dict['time_stamp'] = timestamp
                    data_dict['device_serial'] = self.serial
                    data_dict['device_name'] = self.sys_name
                    data_dict['index'] = index_id
                    data_dict['event_type'] = event_type
                    data_dict['conference_guid'] = conference_guid
                    data_dict['max_simultaneous_audio_video_participants'] = max_simultaneous_audio_video_participants
                    data_dict['max_simultaneous_audio_only_participants'] = max_simultaneous_audio_only_participants
                    data_dict['total_audio_video_participants'] = total_audio_video_participants
                    data_dict['total_audio_only_participants'] = total_audio_only_participants
                    data_dict['session_duration'] = session_duration
                    data_dict['record_type'] = 'cdr_cisco_tps'
                    data_dict['record_key'] = record_key

                    record_string = dumps(data_dict)

            except Exception as e:
                return e
            # END CDR type conferenceInactive

            # CDR type participantMediaSummary
            try:
                if event_type == "participantMediaSummary":
                    video_codecs_list = []
                    audio_codecs_list = []
                    participant_guid = base_cdr_path['value']['struct']['member'][0]['value']['string']
                    call_id = base_cdr_path['value']['struct']['member'][1]['value']['string']
                    streams = base_cdr_path['value']['struct']['member'][2]['value']['array']['data'][
                        'value']

                    stream_number = 0
                    for stream in streams:
                        stream_number += 1
                        stream_direction = stream['struct']['member'][0]['value']['string']
                        stream_type = stream['struct']['member'][1]['value']['string']
                        stream_context = stream['struct']['member'][2]['value']['string']
                        stream_encrypt_status = stream['struct']['member'][4]['value']['string']
                        # Video stream
                        if stream_type == "video":
                            # If stream is a dict
                            if (type(stream['struct']['member'][5]['value']['array'] \
                                             ['data']['value']) == OrderedDict):
                                stream_root = stream['struct']['member'][5]['value']['array'] \
                                    ['data']['value']['struct']['member']
                                stream_video_codec = stream_root[0]['value']['string']
                                stream_video_codec_active_time = stream_root[1]['value']['int']
                                stream_video_codec_encrypt_time = stream_root[2]['value']['int']

                                video_codec_dict = OrderedDict()
                                video_codec_dict['codec'] = stream_video_codec
                                video_codec_dict['active_time'] = stream_video_codec_active_time
                                video_codec_dict['encrypted_time'] = stream_video_codec_encrypt_time

                                stream_video_width = stream['struct']['member'][6]['value']['int']
                                stream_video_height = stream['struct']['member'][7]['value']['int']
                                stream_video_max_bw = stream['struct']['member'][8]['value']['int']
                                stream_video_bw = stream['struct']['member'][9]['value']['int']
                                stream_video_packets_recv = stream['struct']['member'][10]['value']['int']
                                if stream_direction == "rx":
                                    stream_video_packets_lost = stream['struct']['member'][11]['value']['int']
                                else:
                                    stream_video_packets_lost = 0

                                video_stream_out_dict = OrderedDict()
                                video_stream_out_dict['stream_number'] = stream_number
                                video_stream_out_dict['direction'] = stream_direction
                                video_stream_out_dict['type'] = stream_type
                                video_stream_out_dict['context'] = stream_context
                                video_stream_out_dict['encryption_status'] = stream_encrypt_status
                                video_stream_out_dict['codec'] = video_codec_dict
                                video_stream_out_dict['width'] = stream_video_width
                                video_stream_out_dict['height'] = stream_video_height
                                video_stream_out_dict['maximum_bandwidth'] = stream_video_max_bw
                                video_stream_out_dict['bandwidth'] = stream_video_bw
                                video_stream_out_dict['packets_received'] = stream_video_packets_recv
                                video_stream_out_dict['packets_lost'] = stream_video_packets_lost

                                stream_list.append(video_stream_out_dict)

                            # If stream is a list
                            elif (type(stream['struct']['member'][5]['value']['array'] \
                                               ['data']['value']) == list):

                                y = 0

                                for item in stream['struct']['member'][5]['value']['array'] \
                                        ['data']['value']:
                                    video_codec = stream['struct']['member'][5]['value']['array'] \
                                        ['data']['value'][y]['struct']['member'][0]['value']['string']
                                    video_codec_active_time = stream['struct']['member'][5]['value']['array'] \
                                        ['data']['value'][y]['struct']['member'][1]['value']['int']
                                    video_codec_encrypt_time = stream['struct']['member'][5]['value']['array'] \
                                        ['data']['value'][y]['struct']['member'][2]['value']['int']

                                    video_codec_dict = OrderedDict()
                                    video_codec_dict['codec'] = video_codec
                                    video_codec_dict['active_time'] = video_codec_active_time
                                    video_codec_dict['encrypted_time'] = video_codec_encrypt_time
                                    video_codecs_list.append(video_codec_dict)
                                    y += 1

                                stream_video_width = stream['struct']['member'][6]['value']['int']
                                stream_video_height = stream['struct']['member'][7]['value']['int']
                                stream_video_max_bw = stream['struct']['member'][8]['value']['int']
                                stream_video_bw = stream['struct']['member'][9]['value']['int']
                                stream_video_packets_recv = stream['struct']['member'][10]['value']['int']
                                if stream_direction == "rx":
                                    stream_video_packets_lost = stream['struct']['member'][11]['value']['int']
                                else:
                                    stream_video_packets_lost = 0

                                video_stream_out_dict = OrderedDict()
                                video_stream_out_dict['stream_number'] = stream_number
                                video_stream_out_dict['direction'] = stream_direction
                                video_stream_out_dict['type'] = stream_type
                                video_stream_out_dict['context'] = stream_context
                                video_stream_out_dict['encryption_status'] = stream_encrypt_status
                                video_stream_out_dict['codec'] = video_codecs_list
                                video_stream_out_dict['width'] = stream_video_width
                                video_stream_out_dict['height'] = stream_video_height
                                video_stream_out_dict['maximum_bandwidth'] = stream_video_max_bw
                                video_stream_out_dict['bandwidth'] = stream_video_bw
                                video_stream_out_dict['packets_received'] = stream_video_packets_recv
                                video_stream_out_dict['packets_lost'] = stream_video_packets_lost

                                stream_list.append(video_stream_out_dict)

                        # Audio stream
                        if stream_type == "audio":
                            # If stream codec is a dict
                            if (type(stream['struct']['member'][5]['value']['array'] \
                                             ['data']['value']) == OrderedDict):
                                stream_audio_codec = stream['struct']['member'][5]['value']['array'] \
                                    ['data']['value']['struct']['member'][0]['value'] \
                                    ['string']
                                stream_audio_codec_active_time = stream['struct']['member'][5]['value']['array'] \
                                    ['data']['value']['struct']['member'][1]['value']['int']
                                stream_audio_codec_encrypt_time = stream['struct']['member'][5]['value']['array'] \
                                    ['data']['value']['struct']['member'][2]['value']['int']

                                audio_codec_dict = OrderedDict()
                                audio_codec_dict['codec'] = stream_audio_codec
                                audio_codec_dict['active_time'] = stream_audio_codec_active_time
                                audio_codec_dict['encrypted_time'] = stream_audio_codec_encrypt_time

                                stream_audio_max_bw = stream['struct']['member'][6]['value']['int']
                                stream_audio_bw = stream['struct']['member'][7]['value']['int']
                                stream_audio_packets_recv = stream['struct']['member'][8]['value']['int']
                                if stream_direction == "rx":
                                    stream_audio_packets_lost = stream['struct']['member'][9]['value']['int']
                                else:
                                    stream_audio_packets_lost = 0

                                audio_stream_out_dict = OrderedDict()
                                audio_stream_out_dict['stream_number'] = stream_number
                                audio_stream_out_dict['direction'] = stream_direction
                                audio_stream_out_dict['type'] = stream_type
                                audio_stream_out_dict['context'] = stream_context
                                audio_stream_out_dict['encryption_status'] = stream_encrypt_status
                                audio_stream_out_dict['codec'] = audio_codec_dict
                                audio_stream_out_dict['maximum_bandwidth'] = stream_audio_max_bw
                                audio_stream_out_dict['bandwidth'] = stream_audio_bw
                                audio_stream_out_dict['packets_received'] = stream_audio_packets_recv
                                audio_stream_out_dict['packets_lost'] = stream_audio_packets_lost

                                stream_list.append(audio_stream_out_dict)

                            # If stream codec is a list
                            elif (type(stream['struct']['member'][5]['value']['array'] \
                                               ['data']['value']) == list):

                                y = 0
                                for item in stream['struct']['member'][5]['value']['array'] \
                                        ['data']['value']:
                                    audio_codec = (stream['struct']['member'][5]['value']['array'] \
                                                      ['data']['value'][y]['struct']['member'][0]['value'][
                                                      'string'])
                                    codec_active_time = (stream['struct']['member'][5]['value']['array'] \
                                                           ['data']['value'][y]['struct']['member'][1]['value'][
                                                           'int'])
                                    encrypt_time = (stream['struct']['member'][5]['value']['array'] \
                                                      ['data']['value'][y]['struct']['member'][2]['value']['int'])

                                    audio_codec_dict = OrderedDict()
                                    audio_codec_dict['codec'] = audio_codec
                                    audio_codec_dict['active_time'] = codec_active_time
                                    audio_codec_dict['encrypted_time'] = encrypt_time

                                    audio_codecs_list.append(audio_codec_dict)

                                    y += 1

                                stream_audio_max_bw = stream['struct']['member'][6]['value']['int']
                                stream_audio_bw = stream['struct']['member'][7]['value']['int']
                                stream_audio_packets_recv = stream['struct']['member'][8]['value']['int']

                                if stream_direction == "rx":
                                    stream_audio_packets_lost = stream['struct']['member'][9]['value']['int']
                                else:
                                    stream_audio_packets_lost = 0

                                audio_stream_out_dict = OrderedDict()
                                audio_stream_out_dict['stream_number'] = stream_number
                                audio_stream_out_dict['direction'] = stream_direction
                                audio_stream_out_dict['type'] = stream_type
                                audio_stream_out_dict['context'] = stream_context
                                audio_stream_out_dict['encryption_status'] = stream_encrypt_status
                                audio_stream_out_dict['codec'] = audio_codecs_list
                                audio_stream_out_dict['maximum_bandwidth'] = stream_audio_max_bw
                                audio_stream_out_dict['bandwidth'] = stream_audio_bw
                                audio_stream_out_dict['packets_received'] = stream_audio_packets_recv
                                audio_stream_out_dict['packets_lost'] = stream_audio_packets_lost

                                stream_list.append(audio_stream_out_dict)

                    data_dict = OrderedDict()
                    data_dict['time_stamp'] = timestamp
                    data_dict['device_serial'] = self.serial
                    data_dict['device_name'] = self.sys_name
                    data_dict['index'] = index_id
                    data_dict['event_type'] = event_type
                    data_dict['participant_guid'] = participant_guid
                    data_dict['call_id'] = call_id
                    data_dict['streams'] = stream_list
                    data_dict['record_type'] = 'cdr_cisco_tps'
                    data_dict['record_key'] = record_key

                    record_string = dumps(data_dict)


            except Exception as e:
                return e
            # END CDR type participantMediaSummary

            self.cdr_last_read_index = index_id
            self.cdr_jar.append(record_string)

        if int(self.cdr_events_remaining) > 0:
            self.get_cdrs()
        else:
            pass


class CiscoISDN(object):
    def __init__(self, api_host="127.0.0.1", api_user="admin", api_pass="password", secure_conn=True):
        self.api_host = str(api_host)
        self.api_user = str(api_user)
        self.api_pass = str(api_pass)
        self.secure_conn = secure_conn

        # Resultant URLs
        if self.secure_conn is True:
            self.url_auth = "https://" + str(self.api_host) + "/login_change.html"
        elif self.secure_conn is False:
            self.url_auth = "http://" + str(self.api_host) + "/login_change.html"

    def export_config(self):
        """
        Connects to the web interface of the ISDN GW, and pulls the configuration.xml file which it returns.
        :return:
        """

        # Post credentials, and the requested page to the login form
        host_session = requests.session()
        post_data = {'user_name': self.api_user, 'password': self.api_pass, 'requested_page': 'configuration.xml'}
        try:
            host_response = host_session.post(self.url_auth, data=post_data, verify=False, timeout=10)
        except (requests.Timeout, requests.ConnectionError) as e:
            return

        return host_response.text


class CiscoExp(object):
    def __init__(self, api_host="127.0.0.1", api_user="admin", api_pass="password"):
        self.api_host = str(api_host)
        self.api_user = str(api_user)
        self.api_pass = str(api_pass)

        # Resultant URLs
        self.url_status = "https://" + str(self.api_host) + "/status.xml"
        self.url_config = "https://" + str(self.api_host) + "/configuration.xml"

        # Exp object properties
        self.serial = None

        # Call get_properties method to initialise the Exp object properties
        self.get_properties()

    def export_xconf(self):
        """
        Connects to the VCS/EXP via SSH, executes xconfiguration and returns the output
        :return:
        """
        client = SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(self.api_host, username=self.api_user, password=self.api_pass, banner_timeout=5)
        client_shell = client.invoke_shell()
        client_shell.recv(2048)
        sleep(2)
        client_shell.send("xconfiguration\n")
        sleep(2)
        output = client_shell.recv(5242880)
        client.close()
        return output.decode("utf-8")

    def export_xstatus(self):
        """
        Connects to the VCS/EXP via SSH, executes xstatus and returns the output
        :return:
        """
        client = SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(self.api_host, username=self.api_user, password=self.api_pass, banner_timeout=5)
        client_shell = client.invoke_shell()
        client_shell.recv(2048)
        sleep(2)
        client_shell.send("xstatus\n")
        sleep(2)
        output = client_shell.recv(81920)
        client.close()
        return output.decode("utf-8")

    def get_properties(self):
        ns = {'ns': 'http://www.tandberg.no/XML/CUIL/1.0'}
        host_session = requests.session()
        host_session.auth = str(self.api_user), str(self.api_pass)

        try:
            status_response = host_session.get(self.url_status, verify=False, timeout=10)
            status_xml = etree.fromstring(status_response.text)
        except Exception as e:
            return e

        self.serial = status_xml.find(
            "ns:SystemUnit[@item='1']/ns:Hardware[@item='1']/ns:SerialNumber[@item='1']", namespaces=ns).text

    def get_license_util(self):
        """
        Get current license utilisation and device details and returns as a JSON string.
        :return:
        """
        ns = {'ns': 'http://www.tandberg.no/XML/CUIL/1.0'}
        url_statusxml = "https://" + str(self.api_host) + "/status.xml"
        url_configxml = "https://" + str(self.api_host) + "/configuration.xml"
        host_session = requests.session()
        host_session.auth = str(self.api_user), str(self.api_pass)

        data_dict = OrderedDict()

        try:
            status_response = host_session.get(url_statusxml, verify=False, timeout=10)
            status_xml = etree.fromstring(status_response.text)
        except Exception as e:
            return e

        try:
            config_response = host_session.get(url_configxml, verify=False, timeout=10)
            config_xml = etree.fromstring(config_response.text)
        except Exception as e:
            return e

        current_call_count = 0
        calls = status_xml.find("ns:Calls[@item='1']", namespaces=ns)
        for call in calls:
            current_call_count += 1

        data_dict['time_stamp'] = str(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S'))
        data_dict['device_serial'] = status_xml.find(
            "ns:SystemUnit[@item='1']/ns:Hardware[@item='1']/ns:SerialNumber[@item='1']", namespaces=ns)
        data_dict['device_name'] = str(config_xml.find("ns:SystemUnit[@item='1']/ns:Name", namespaces=ns))
        data_dict['traversal_in_use'] = str(status_xml.find(
            "ns:ResourceUsage[@item='1']/ns:Calls[@item='1']/ns:Traversal[@item='1']/ns:Current[@item='1']",
            namespaces=ns))
        data_dict['traversal_limit'] = str(status_xml.find(
            "ns:SystemUnit[@item='1']/ns:Software[@item='1']/ns:Configuration[@item='1']/ns:TraversalCalls[@item='1']",
            namespaces=ns))
        data_dict['non_traversal_in_use'] = str(status_xml.find(
            "ns:ResourceUsage[@item='1']/ns:Calls[@item='1']/ns:NonTraversal[@item='1']/ns:Current[@item='1']",
            namespaces=ns))
        data_dict['non_traversal_limit'] = str(status_xml.find(
            "ns:SystemUnit[@item='1']/ns:Software[@item='1']/ns:Configuration[@item='1']"
            "/ns:NonTraversalCalls[@item='1']",
            namespaces=ns))
        data_dict['current_registrations'] = str(status_xml.find(
            "ns:ResourceUsage[@item='1']/ns:Registrations[@item='1']/ns:Current[@item='1']", namespaces=ns))
        data_dict['concurrent_calls'] = str(current_call_count)
        data_dict['record_type'] = 'util_cisco_expressway_license'
        data_dict['record_key'] = str(data_dict['device_serial']) + \
                                  "_" + str(datetime.utcnow().strftime('%Y%m%d%H%M%S'))

        return dumps(data_dict)