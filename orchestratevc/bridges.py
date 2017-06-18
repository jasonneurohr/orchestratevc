
import requests
import xmltodict
import datetime


class Bridges:
    """General VC Bridge superclass.
    """

    def __init__(self, api_host, api_user, api_pass, api_port='443'):
        """Initialise a Bridges object

        Args:
            __api_host (str): IP address or resolvable name of the device.
            __api_port (str): TCP port where the API/XML is accessible.
                Defaults to port 443
            __api_user (str): Username to access the device.
            __api_pass (str): Password to access the device.
        """

        self.__api_host = str(api_host)
        self.__api_port = str(api_port)
        self.__api_user = str(api_user)
        self.__api_pass = str(api_pass)


    def get_api_host(self):
        """Return __api_host
        """
        return self.__api_host

    def get_api_port(self):
        """Return __api_port
        """
        return self.__api_port

    def get_api_user(self):
        """Return __api_user
        """
        return self.__api_user

    def get_api_pass(self):
        """Return __api_pass
        """
        return self.__api_pass


class Cms(Bridges):
    """Cisco Meeting Server (CMS) subclass

    Methods:
        ~ accessMethods:
            del_am(self, space_id, am_id)
            set_am(self, space_id, am_id=None, properties=None)
            get_am(self, space_id, am_id)
        ~ callLegs
            get_legs(self, call_id=None)
            get_leg(self, leg_id)
            mod_leg(self, leg_id)
        ~ callLegProfiles:
        ~ callProfiles:
            get_cps(self)
            get_cp(self, cp_id)
        ~ calls:
            conf_count(self)
            get_calls(self, limit=None, offset=None)
            get_call(self, call_id)
        ~ coSpaces:
            query_spaces(self, query, limit=None, offset=None)
        ~ misc:
            valid_certificate(self)
        ~ system:
            get_licensing(self)

    """

    def __init__(self, api_host, api_user, api_pass, api_port='443'):
        """Initialise a Cms object
        Call the superclass's __init__ method and pass the required
        arguments.

        self.__ssl_is_valid will call the valid_certificate(self) method,
        to determine whether the CMS certificate is valid.

        Args:
            __api_host (str): IP address or resolvable name of the device.
            __api_port (str): TCP port where the API/XML is accessible.
                Defaults to port 443
            __api_user (str): Username to access the device.
            __api_pass (str): Password to access the device.
        """

        Bridges.__init__(self, api_host, api_user, api_pass, api_port)

        self.__url_api = "https://{api_host}:{api_port}/api/v1/".format(
            api_host=self.get_api_host(),
            api_port=self.get_api_port()
        )

        self.__url_api_clps = self.__url_api + 'calllegprofiles' # callLegProfiles
        self.__url_api_cps = self.__url_api + 'callprofiles' # callProfiles
        self.__url_api_calls = self.__url_api + 'calls'
        self.__url_api_calllegs = self.__url_api + 'calllegs'
        self.__url_api_cospaces = self.__url_api + 'cospaces'
        self.__url_api_mlic = self.__url_api + 'system/multipartyLicensing' # multipartyLicensing
        self.__ssl_is_valid = self.valid_certificate()

    def valid_certificate(self):
        """Check certificate validity

        Returns:
            bool: True if certificate is valid. Otherwise False
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        try:
            resp = s.get(self.__url_api_calls, timeout=10)
        except requests.exceptions.SSLError as err:
            # SSL Cert is invalid, fall back to non-verify
            return False
        return True

    def get_spaces(self):
        """Get coSpace objects

        """

        api_session = requests.session()
        api_session.auth = self.get_api_user(), self.get_api_pass()
        api_response = api_session.get(self.__url_api_cospaces, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response.text)
        total_spaces = int(xml_api_response['coSpaces']['@total'])
        space_dict = {}

        # No spaces
        if total_spaces == 0:
            return

        # Only 1 space
        if total_spaces == 1:
            space_id = xml_api_response['coSpaces']['coSpace']['@id']
            space_name = xml_api_response['coSpaces']['coSpace']['name']
            space_dict[space_id] = space_name
            return space_dict

        # More then 1 space
        if total_spaces > 1:
            offset = 0
            while offset != total_spaces:
                req_url = self.__url_api_cospaces + '?offset=' + str(offset) + '&limit=10'
                api_response = api_session.get(req_url, verify=False, timeout=10)
                xml_api_response = xmltodict.parse(api_response.text)

                # Get the initial response items
                for space in xml_api_response['coSpaces']['coSpace']:
                    offset += 1  # Increment the offset for each record return
                    space_id = space['@id']
                    space_name = space['name']
                    space_dict[space_id] = space_name
            return space_dict
        api_session.close()

    def get_space_callprofile(self, space_id):
        """
        """

        req_url = self.__url_api_cospaces + '/' + space_id
        api_session = requests.session()
        api_session.auth = self.get_api_user(), self.get_api_pass()
        api_response = api_session.get(req_url, verify=False, timeout=10)
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
        """Get all accessMethod objects for a given cospace id

        Args:
            space_id (str): cospace id
        """

        accessmethod_ids = []
        req_url = self.__url_api_cospaces + '/' + space_id + "/accessmethods/"
        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        try:
            resp = s.get(req_url, verify=self.__ssl_is_valid, timeout=10)
            xml_resp = xmltodict.parse(resp.text)
        except Exception as err:
            return err

        total_accessmethods = int(xml_resp['accessMethods']['@total'])

        if total_accessmethods == 0:  # NO ACCESS METHODS.... RETURN
            return
        if total_accessmethods == 1:
            accessmethod_id = xml_resp['accessMethods']['accessMethod']['@id']
            return accessmethod_id
        if total_accessmethods > 1:
            for accessmethod in xml_resp['accessMethods']['accessMethod']:
                accessmethod_ids.append(accessmethod['@id'])
            return accessmethod_ids

    def get_space_calllegprofiles(self, space_id, accessmethod_id):
        """
        """

        api_session = requests.session()
        api_session.auth = self.get_api_user(), self.get_api_pass()
        api_response = api_session.get(self.__url_api_cospaces, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response.text)
        try:
            calllegprofile_id = xml_api_response['accessMethod']['callLegProfile']
            return calllegprofile_id
        except:
            return

    def conf_count(self):
        """Get the total number of conferences

        Returns:
            int: total conference count
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        try:
            resp = s.get(self.__url_api_calls, verify=self.__ssl_is_valid, timeout=10)
        except Exception as err:
            return err
        xml_resp = xmltodict.parse(resp.text)

        try:
            total_conferences = xml_resp['calls']['@total']
        except Exception as err:
            return 0

        return int(total_conferences)

    def set_all_calllegprofile_properties(self, properties=None):
        """
        """

        api_session = requests.session()
        api_session.auth = self.get_api_user(), self.get_api_pass()
        api_response = api_session.get(self.__url_api_clps, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response.text)
        total_profiles = int(xml_api_response['callLegProfiles']['@total'])

        if total_profiles == 0:  # No profiles
            return

        if total_profiles == 1:  # Only 1 profile
            calllegprofile_id = xml_api_response['callLegProfiles']['callLegProfile']['@id']
            url_secure_api = self.__url_api_clps + '/' + calllegprofile_id
            api_response = api_session.put(url_secure_api, data=properties, verify=False, timeout=10)
            return

        offset = 0
        while offset != total_profiles:
            url_secure_api = self.__url_api_clps + '?offset=' + str(offset) + '&limit=10'
            api_response = api_session.get(url_secure_api, verify=False, timeout=10)
            xml_api_response = xmltodict.parse(api_response.text)

            for calllegprofile in xml_api_response['callLegProfiles']['callLegProfile']:
                offset += 1
                calllegprofile_id = str(calllegprofile['@id'])
                url_secure_api = self.__url_api_clps + '/' + calllegprofile_id
                api_response = api_session.put(url_secure_api, data=properties, verify=False, timeout=10)
                print(api_response.text)
        return

    def del_spaces_and_artifacts(self, filter_string=None):
        api_session = requests.session()
        api_session.auth = self.get_api_user(), self.get_api_pass()
        api_response = api_session.get(self.__url_api_cospaces, verify=False, timeout=10)
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
                req_url = self.__url_api_cps + "/" + callprofile_id
                api_session.delete(req_url, verify=False, timeout=10)

            accessmethod_ids = self.get_space_accessmethods(space_id)

            if type(accessmethod_ids) == str:  # Only 1 accessmethod
                calllegprofile_id = self.get_space_calllegprofiles(space_id, accessmethod_ids)
                if callprofile_id is not None:
                    req_url = self.__url_api_clps + '/' + calllegprofile_id
                    api_session.delete(req_url, verify=False, timeout=10)

            if type(accessmethod_ids) == list:  # Multiple access methods
                for accessmethod_id in accessmethod_ids:
                    calllegprofile_id = self.get_space_calllegprofiles(space_id,accessmethod_id)
                    if calllegprofile_id is not None:
                        req_url = self.__url_api_clps + '/' + calllegprofile_id
                        api_session.delete(req_url, verify=False, timeout=10)

            # Finally delete the space (and subsequently the access methods)
            req_url = self.__url_api_cospaces + '/' + space_id
            api_session.delete(req_url, verify=False, timeout=10)

        if total_spaces > 1:
            for space in xml_api_response['coSpaces']['coSpace']:
                space_id = str(space['@id'])
                callprofile_id = self.get_space_callprofile(space_id)

                # Check if the space ID is in the filter list, if True pass
                if space_id in filter_string:
                    pass
                else:
                    if callprofile_id is not None:  # Space has a profile which will be deleted
                        req_url = self.__url_api_cps + '/' + callprofile_id
                        api_session.delete(req_url, verify=False, timeout=10)

                    accessmethod_ids = self.get_space_accessmethods(space_id)

                    if type(accessmethod_ids) == str:  # Only 1 accessmethod
                        calllegprofile_id = self.get_space_calllegprofiles(space_id, accessmethod_id)
                        if callprofile_id is not None:
                            req_url = self.__url_api_clps + '/' + calllegprofile_id
                            api_session.delete(req_url, verify=False, timeout=10)

                    if type(accessmethod_ids) == list:  # Multiple access methods
                        for accessmethod_id in accessmethod_ids:
                            calllegprofile_id = self.get_space_calllegprofiles(space_id, accessmethod_id)
                            if calllegprofile_id is not None:
                                req_url = self.__url_api_clps + '/' + calllegprofile_id
                                api_session.delete(req_url, verify=False, timeout=10)

                    # Finally delete the space (and subsequently the access methods)
                    req_url = self.__url_api_cospaces + '/' + space_id
                    api_session.delete(req_url, verify=False, timeout=10)

    def set_am(self, space_id, am_id=None, properties=None):
        """Set Access Method properties

        If no accessMethod id is specified a new access method will be created.
        If accessMethod id is specified any defined properties will be set.

        Args:
            space_id (str): cospace id
            am_id (str): accessMethod id if existing
            properties (dict): dictionary of accessMethod properties (if any)

        Returns:
            bool: True for success. False otherwise
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()

        if am_id is None:
            # accessMethod doesn't already exist. POST
            req_url = self.__url_api_cospaces + '/' + space_id + '/accessmethods/'
            try:
                resp = s.post(req_url, verify=self.__ssl_is_valid, data=properties, timeout=10)
            except Exception as err:
                return err
            return True
        else:
            # Existing accessMethod. PUT
            req_url = self.__url_api_cospaces + '/' + space_id + '/accessmethods/' + am_id
            try:
                resp = s.put(req_url, verify=self.__ssl_is_valid, data=properties, timeout=10)
            except Exception as err:
                return err
            if resp.status_code == 400:
                # accessMethod doesn't exist
                # API response should be:
                # <?xml version="1.0"?><failureDetails><accessMethodDoesNotExist /></failureDetails>
                return False
            return True

    def del_am(self, space_id, am_id):
        """Delete an Access Method

        Args:
            space_id (str): cospace id
            am_id (str): accessMethod id if existing

        Returns:
            bool: True for success. False otherwise
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()

        req_url = self.__url_api_cospaces + '/' + space_id + '/accessmethods/' + am_id
        try:
            resp = s.delete(req_url, verify=self.__ssl_is_valid, timeout=10)
        except Exception as err:
            return err
        if resp.status_code == 400:
            # accessMethod doesn't exist
            # API response should be:
            # <?xml version="1.0"?><failureDetails><accessMethodDoesNotExist /></failureDetails>
            return False
        return True

    def get_am(self, space_id, am_id):
        """Get an Access Methods Properties

        Args:
            space_id (str): cospace id
            am_id (str): accessMethod id if existing
        """

    def query_spaces(self, query, limit=None, offset=None):
        """Query all spaces

        Args:
            query (str): the query string
            limit (int): object return limit
            offset (int): object offset limit

        Returns:
            dict: dictionary of 'coSpace id':'coSpace name' k:v pairs
        """

        space_dict = {}
        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()

        req_url = self.__url_api_cospaces + '?filter=' + str(query)

        if limit != None:
            req_url += '&limit=' + str(limit)
        if offset != None:
            req_url += '&offset=' + str(offset)

        try:
            resp = s.get(req_url, verify=self.__ssl_is_valid, timeout=10)
        except Exception as err:
            return err

        xml_resp = xmltodict.parse(resp.text)
        total_spaces = int(xml_resp['coSpaces']['@total'])

        if total_spaces == 0:
            return
        elif total_spaces == 1:
            space_id = xml_resp['coSpaces']['coSpace']['@id']
            space_name = xml_resp['coSpaces']['coSpace']['name']
            space_dict[space_id] = space_name
            return space_dict
        elif total_spaces > 1:
            for space in xml_resp['coSpaces']['coSpace']:
                space_dict[space['@id']] = space['name']
            return space_dict

    def get_calls(self, limit=None, offset=None):
        """Get all calls

        Args:
            query (str): the query string
            limit (int): object return limit
        
        Returns:
            dict: a dict containing call records
        """

        calls = dict()

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        req_url = self.__url_api_calls

        try:
            resp = s.get(req_url, verify=self.__ssl_is_valid, timeout=10)
            xml_resp = xmltodict.parse(resp.text)
        except Exception as err:
            return err
        
        if int(xml_resp['calls']['@total']) == 1:
            call_id = xml_resp['calls']['call']['@id']
            calls[call_id] = {
                'name': xml_resp['calls']['call']['name'],
                'coSpace': xml_resp['calls']['call']['coSpace'],
                'callCorrelator': xml_resp['calls']['call']['callCorrelator']}

        elif int(xml_resp['calls']['@total']) > 1:
            for call in xml_resp['calls']['call']:
                call_id = call['@id']
                calls[call_id] = {
                    "name": call['name'],
                    "coSpace": call['coSpace'],
                    "callCorrelator": call['callCorrelator']}

        return calls

    
    def get_call(self, call_id):
        """Get specific call details

        Args:
            call_id (str): the call id
            limit (int): object return limit

        Returns:
        """
    
    def get_cps(self):
        """Get all call profiles

        Args:

        Returns:
        """
    def get_cp(self, cp_id):
        """Get specific call profile

        Args:
            cp_id (str): call profile id

        Returns:
        """

    def get_legs(self, call_id=None):
        """Get call legs

        Limit to a specific call by passing the call_id

        Args:
            call_id (str): the call id if specified

        Returns:
        """

        call_legs = dict()

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        req_url = self.__url_api_calls + '/' + call_id + '/calllegs/' 

        try:
            resp = s.get(req_url, verify=self.__ssl_is_valid, timeout=10)
            xml_resp = xmltodict.parse(resp.text)
        except Exception as err:
            return err
        
        if int(xml_resp['callLegs']['@total']) == 1:
            call_leg_id = xml_resp['callLegs']['callLeg']['@id']
            call_legs[call_leg_id] = {
                'name': xml_resp['callLegs']['callLeg']['name'],
                'remoteParty': xml_resp['callLegs']['callLeg']['remoteParty'],
                'call': xml_resp['callLegs']['callLeg']['call']}

        elif int(xml_resp['callLegs']['@total']) > 1:
            for call_leg in xml_resp['calls']['call']: #TODO
                call_leg_id = call_leg['@id']
                call_legs[call_leg_id] = {
                    "name": call_legs['name'],
                    "remoteParty": call_legs['remoteParty'],
                    "call": call_legs['call']}

        return call_legs

    def get_correlated(self, call_correlator):
        """Get call ID from call matching the callCorrelator ID

        Args:
            call_correlator (str): callCorrelator ID

        Returns:
            str: call ID
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        req_url = self.__url_api_calls

        try:
            resp = s.get(req_url, verify=self.__ssl_is_valid, timeout=10)
            xml_resp = xmltodict.parse(resp.text)
        except Exception as err:
            return err

        total_calls = int(xml_resp['calls']['@total'])
        
        if total_calls == 1:
            return xml_resp['calls']['call']['@id']
        if total_calls > 1:
            offset = 0
            while offset != total_calls:
                req_url = self.__url_api_calls + '?offset=' + str(offset) + '&limit=10'
                resp = s.get(req_url, verify=self.__ssl_is_valid, timeout=10)
                xml_resp = xmltodict.parse(resp.text)
                for call in xml_resp['calls']['call']:
                    if call['callCorrelator'] == call_correlator:
                        return call['@id']
                        
        return None

    def get_leg(self, leg_id):
        """Get specific call leg details

        Args:
            leg_id (str): the call leg id

        Returns:
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        req_url = self.__url_api_calllegs + '/' + leg_id

        try:
            resp = s.get(req_url, verify=self.__ssl_is_valid, timeout=10)
            xml_resp = xmltodict.parse(resp.text)
        except Exception as err:
            return err

        root = xml_resp['callLeg']

        leg = dict()
        rxAudio = dict()
        txAudio = dict()
        rxVideo = dict()
        txVideo = dict()
        leg['id'] = root['@id']
        leg['name'] = root['name']
        leg['localAddress'] = root['localAddress']
        leg['direction'] = root['direction']
        leg['durationSeconds'] = root['status']['durationSeconds']
        leg['direction'] = root['status']['direction']
        leg['layout'] = root['status']['layout']
        leg['remoteParty'] = root['remoteParty']
        rxAudio['codec'] = root['status']['rxAudio']['codec']
        rxAudio['packetLossPercentage'] = root['status']['rxAudio']['packetLossPercentage']
        rxAudio['jitter'] = root['status']['rxAudio']['jitter']
        rxAudio['bitRate'] =  root['status']['rxAudio']['bitRate']
        leg['rxAudio'] = rxAudio
        txAudio['codec'] = root['status']['txAudio']['codec']
        txAudio['packetLossPercentage'] = root['status']['txAudio']['packetLossPercentage']
        txAudio['jitter'] = root['status']['txAudio']['jitter']
        txAudio['bitRate'] =  root['status']['txAudio']['bitRate']
        leg['txAudio'] = txAudio
        rxVideo['codec'] = root['status']['rxVideo']['codec']
        rxVideo['packetLossPercentage'] = root['status']['rxVideo']['packetLossPercentage']
        rxVideo['jitter'] = root['status']['rxVideo']['jitter']
        rxVideo['bitRate'] = root['status']['rxVideo']['bitRate']
        rxVideo['width'] = root['status']['rxVideo']['width']
        rxVideo['height'] = root['status']['rxVideo']['height']
        rxVideo['frameRate'] = root['status']['rxVideo']['frameRate']
        leg['rxVideo'] = rxVideo
        txVideo['codec'] = root['status']['txVideo']['codec']
        txVideo['packetLossPercentage'] = root['status']['txVideo']['packetLossPercentage']
        txVideo['jitter'] = root['status']['txVideo']['jitter']
        txVideo['bitRate'] = root['status']['txVideo']['bitRate']
        txVideo['width'] = root['status']['txVideo']['width']
        txVideo['height'] = root['status']['txVideo']['height']
        txVideo['frameRate'] = root['status']['txVideo']['frameRate']
        leg['txVideo'] = txVideo

        return(leg)

    def del_leg(self, leg_id):
        """Delete an active call leg (end a call)

        Args:
            leg_id (str): the call leg id

        Returns:
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        req_url = self.__url_api_calllegs + '/' + leg_id

        try:
            resp = s.delete(req_url, verify=self.__ssl_is_valid, timeout=10)
        except Exception as err:
            return err

    def new_leg(self, call_id, remote_party):
        """Creates a new call leg (new outbound call)

        Args:
            call_id (str): the call id

        Returns:
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        req_url = self.__url_api_calls + '/' + call_id + '/participants'

        data = {'remoteParty': remote_party}

        try:
            resp = s.post(req_url, data=data, verify=self.__ssl_is_valid, timeout=10)
        except Exception as err:
            return err

    def mod_leg(self, leg_id, prop, val):
        """Modify an active call leg

        Args:
            leg_id (str): the call leg id

        Returns:
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        req_url = self.__url_api_calllegs + '/' + leg_id

        data = {prop:val}

        try:
            resp = s.put(req_url, data=data, verify=self.__ssl_is_valid, timeout=10)
            xml_resp = xmltodict.parse(resp.text)
        except Exception as err:
            return err

    def get_licensing(self):
        """Get CMS multipartyLicensing details

        Returns:
            dict: dict of license properties
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()

        try:
            resp = s.get(self.__url_api_mlic, verify=self.__ssl_is_valid, timeout=10)
        except Exception as err:
            return err

        xml_resp = xmltodict.parse(resp.text)['multipartyLicensing']
        # Convert time_stamp str to datetime object for correct insertion into MongoDB
        xml_resp['timestamp'] = datetime.datetime.strptime(
            xml_resp['timestamp'], '%Y-%m-%dT%H:%M:%SZ')

        return xml_resp

class Tps(Bridges):
    """Cisco TelePresence Server subclass

    It is requi
    """

    def __init__(self, api_host, api_user, api_pass, insecure=False):
        """Initialise a Tps object
        Call the superclass's __init__ method and pass the required
        arguments.
        """

        Bridges.__init__(self, api_host, api_user, api_pass)

        # If insecure is True base URL will use HTTP
        if insecure is True:
            self.__url = 'http://{api_host}/'.format(api_host=self.get_api_host())
        else:
            self.__url = 'https://{api_host}/'.format(api_host=self.get_api_host())

        self.__url_api = self.__url + '/RPC2'
        self.__url_sys = self.__url + '/system.xml'
        self.__url_conf = self.__url + '/configuration.xml'
        self.__url_auth = self.__url + '/login_change.html'
        self.__url_logout = self.__url + '/logout.html'
        self.__ssl_is_valid = self.valid_certificate()

        self.__serial = None
        self.__sys_name = None
        self.__utf_offset = None
        self.__build_ver = None
        self.__total_vports = None
        self.__total_aports = None
        self.__total_cports = None

    def valid_certificate(self):
        """Check certificate validity

        Returns:
            bool: True if certificate is valid. Otherwise False
        """

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()
        try:
            resp = s.get(self.__url_sys, timeout=10)
        except requests.exceptions.SSLError as err:
            # SSL Cert is invalid, fall back to non-verify
            return False
        return True

    def __tps_properties(self):
        """Gathers various TPS data
        """

        post_sysinfo = (
            '<methodCall><methodName>system.info</methodName>'
            '<params><param><value><struct><member>'
            '<name>authenticationPassword</name>'
            '<value><string>{}</string></value>'
            '</member><member>'
            '<name>authenticationUser</name>'
            '<value><string>{}</string></value>'
            '</member></struct></value></param></params>'
            '</methodCall>').format(self.get_api_pass(), self.get_api_user())

        s = requests.session()

        try:
            resp = s.get(self.__url_sys, verify=self.__ssl_is_valid, timeout=10)
        except Exception as err:
            return err

        # Get system details from the system.xml
        xml_resp = xmltodict.parse(r.text)
        self.__serial = xml_resp['system']['serial']
        self.__build_ver = xml_resp['system']['buildVersion']
        self.__total_vports = int(xml_resp['system']['totalVideoPorts'])
        self.__total_aports = int(xml_resp['system']['totalAudioPorts'])
        self.__total_cports = int(xml_resp['system']['totalContentPorts'])

        try:
            resp = s.post(self.__url_api, verify=self.__ssl_is_valid, timeout=10)
        except Exception as err:
            return err

        # Get basic system details from the system.info API method
        xml_resp = xmltodict.parse(r.text)
        xml_path = xml_resp["methodResponse"]["params"]["param"]["value"]["struct"]["member"]

        # Conductor/Remotely managed specific
        if xml_path[4]['name'] == 'depHash':
            if self.__build_ver == '13.1(1.95)':
                __vports_free = int(xml_path[10]['value']['int'])
                __vports_used = self.__total_vports - __vports_free
                __aports_free = int(xml_path[12]['value']['int'])
                __aports_used = self.__total_aports - __aports_free
                __cports_free = int(xml_path[14]['value']['int'])
                __cports_used = self.__total_cports - __cports_free
                if xml_path[19]['value']['string'] == 'slave':
                    __license_mode = None
                else:
                    __license_mode = xml_path[20]['value']['string']
        
        # Locally managed mode specific
        else:
            if self.__build_ver == '13.1(1.95)':
                __offset = -1
            else:
                __offset = 0


    def get_serial(self):
        return
    
    def get_system_name(self):
        return
    
    def get_utc_offset(self):
        return
    
    def set_serial(self):
        return
    
    def set__system_name(self):
        return
    
    def set_utc_offset(self):
        return