import datetime
import requests
import xmltodict


class Cms:
    """Cisco Meeting Server (CMS)

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
    def __init__(self, address, username, password, port='443'):
        self.__address = str(address)
        self.__port = str(port)
        self.__username = str(username)
        self.__password = str(password)

        """Initialise a Cms object
        self.__ssl_is_valid will call the valid_certificate(self) method,
        to determine whether the CMS certificate is valid.

        Args:
            __api_host (str): IP address or resolvable name of the device.
            __api_port (str): TCP port where the API/XML is accessible.
                Defaults to port 443
            __api_user (str): Username to access the device.
            __api_pass (str): Password to access the device.
        """

        self.__url_api = "https://{address}:{port}/api/v1/".format(
            address=self.get_address(),
            port=self.get_port()
        )

        self.__url_api_clps = self.__url_api + 'calllegprofiles' # callLegProfiles
        self.__url_api_cps = self.__url_api + 'callprofiles' # callProfiles
        self.__url_api_calls = self.__url_api + 'calls'
        self.__url_api_cospaces = self.__url_api + 'cospaces'
        self.__url_api_mlic = self.__url_api + 'system/multipartyLicensing' # multipartyLicensing
        self.__ssl_is_valid = self.valid_certificate()

    def get_address(self):
        """Return __api_host
        """
        return self.__address

    def get_port(self):
        """Return __api_port
        """
        return self.__port

    def get_username(self):
        """Return __api_user
        """
        return self.__username

    def get_password(self):
        """Return __api_pass
        """
        return self.__password

    def valid_certificate(self):
        """Check certificate validity

        Returns:
            bool: True if certificate is valid. Otherwise False
        """

        s = requests.session()
        s.auth = self.get_username(), self.get_password()
        try:
            resp = s.get(self.__url_api_calls, timeout=10)
        except requests.exceptions.SSLError as err:
            # SSL Cert is invalid, fall back to non-verify
            return False
        return True

    def get_spaces(self):
        """Get coSpace objects
        """

        session = requests.session()
        session.auth = self.get_username(), self.get_password()
        response = session.get(self.__url_api_cospaces, verify=False, timeout=10)
        xml_response = xmltodict.parse(response.text)
        total_spaces = int(xml_response['coSpaces']['@total'])
        space_dict = {}

        # No spaces
        if total_spaces == 0:
            return

        # Only 1 space
        if total_spaces == 1:
            space_id = xml_response['coSpaces']['coSpace']['@id']
            space_name = xml_response['coSpaces']['coSpace']['name']
            space_dict[space_id] = space_name
            return space_dict

        # More then 1 space
        if total_spaces > 1:
            offset = 0
            while offset != total_spaces:
                req_url = self.__url_api_cospaces + '?offset=' + str(offset) + '&limit=10'
                response = session.get(req_url, verify=False, timeout=10)
                xml_response = xmltodict.parse(response.text)

                # Get the initial response items
                for space in xml_response['coSpaces']['coSpace']:
                    offset += 1  # Increment the offset for each record return
                    space_id = space['@id']
                    space_name = space['name']
                    space_dict[space_id] = space_name
            return space_dict
        session.close()

    def get_space_callprofile(self, space_id):
        """
        """

        req_url = self.__url_api_cospaces + '/' + space_id
        session = requests.session()
        session.auth = self.get_username(), self.get_password()
        response = session.get(req_url, verify=False, timeout=10)
        xml_response = xmltodict.parse(response.text)

        try:
            callprofile_id = xml_response['coSpace']['callProfile']
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
        session = requests.session()
        session.auth = self.get_username(), self.get_password()
        try:
            resp = session.get(req_url, verify=self.__ssl_is_valid, timeout=10)
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

        session = requests.session()
        session.auth = self.get_username(), self.get_password()
        response = session.get(self.__url_api_cospaces, verify=False, timeout=10)
        xml_response = xmltodict.parse(response.text)
        try:
            calllegprofile_id = xml_response['accessMethod']['callLegProfile']
            return calllegprofile_id
        except:
            return

    def conf_count(self):
        """Get the total number of conferences

        Returns:
            int: total conference count
        """

        session = requests.session()
        session.auth = self.get_username(), self.get_password()
        try:
            resp = session.get(self.__url_api_calls, verify=self.__ssl_is_valid, timeout=10)
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

        session = requests.session()
        session.auth = self.get_username(), self.get_password()
        response = session.get(self.__url_api_clps, verify=False, timeout=10)
        xml_response = xmltodict.parse(response.text)
        total_profiles = int(xml_response['callLegProfiles']['@total'])

        if total_profiles == 0:  # No profiles
            return

        if total_profiles == 1:  # Only 1 profile
            calllegprofile_id = xml_response['callLegProfiles']['callLegProfile']['@id']
            url_secure_api = self.__url_api_clps + '/' + calllegprofile_id
            response = session.put(url_secure_api, data=properties, verify=False, timeout=10)
            return

        offset = 0
        while offset != total_profiles:
            url_secure_api = self.__url_api_clps + '?offset=' + str(offset) + '&limit=10'
            response = session.get(url_secure_api, verify=False, timeout=10)
            xml_response = xmltodict.parse(response.text)

            for calllegprofile in xml_response['callLegProfiles']['callLegProfile']:
                offset += 1
                calllegprofile_id = str(calllegprofile['@id'])
                url_secure_api = self.__url_api_clps + '/' + calllegprofile_id
                response = session.put(url_secure_api, data=properties, verify=False, timeout=10)
                print(response.text)
        return

    def del_spaces_and_artifacts(self, filter_string=None):
        session = requests.session()
        session.auth = self.get_username(), self.get_password()
        response = session.get(self.__url_api_cospaces, verify=False, timeout=10)
        xml_response = xmltodict.parse(response.text)
        total_spaces = int(xml_response['coSpaces']['@total'])

        if total_spaces == 0:  # No spaces
            return

        if total_spaces == 1:
            space_id = str(xml_response['coSpaces']['coSpace']['@id'])
            callprofile_id = self.get_space_callprofile(space_id)

            # Check if the space ID is in the filter list, if True return
            if space_id in filter_string:
                return

            if callprofile_id is not None:  # Space has a profile which will be deleted
                req_url = self.__url_api_cps + "/" + callprofile_id
                session.delete(req_url, verify=False, timeout=10)

            accessmethod_ids = self.get_space_accessmethods(space_id)

            if type(accessmethod_ids) == str:  # Only 1 accessmethod
                calllegprofile_id = self.get_space_calllegprofiles(space_id, accessmethod_ids)
                if callprofile_id is not None:
                    req_url = self.__url_api_clps + '/' + calllegprofile_id
                    session.delete(req_url, verify=False, timeout=10)

            if type(accessmethod_ids) == list:  # Multiple access methods
                for accessmethod_id in accessmethod_ids:
                    calllegprofile_id = self.get_space_calllegprofiles(space_id,accessmethod_id)
                    if calllegprofile_id is not None:
                        req_url = self.__url_api_clps + '/' + calllegprofile_id
                        session.delete(req_url, verify=False, timeout=10)

            # Finally delete the space (and subsequently the access methods)
            req_url = self.__url_api_cospaces + '/' + space_id
            session.delete(req_url, verify=False, timeout=10)

        if total_spaces > 1:
            for space in xml_response['coSpaces']['coSpace']:
                space_id = str(space['@id'])
                callprofile_id = self.get_space_callprofile(space_id)

                # Check if the space ID is in the filter list, if True pass
                if space_id in filter_string:
                    pass
                else:
                    if callprofile_id is not None:  # Space has a profile which will be deleted
                        req_url = self.__url_api_cps + '/' + callprofile_id
                        session.delete(req_url, verify=False, timeout=10)

                    accessmethod_ids = self.get_space_accessmethods(space_id)

                    if type(accessmethod_ids) == str:  # Only 1 accessmethod
                        calllegprofile_id = self.get_space_calllegprofiles(space_id, accessmethod_id)
                        if callprofile_id is not None:
                            req_url = self.__url_api_clps + '/' + calllegprofile_id
                            session.delete(req_url, verify=False, timeout=10)

                    if type(accessmethod_ids) == list:  # Multiple access methods
                        for accessmethod_id in accessmethod_ids:
                            calllegprofile_id = self.get_space_calllegprofiles(space_id, accessmethod_id)
                            if calllegprofile_id is not None:
                                req_url = self.__url_api_clps + '/' + calllegprofile_id
                                session.delete(req_url, verify=False, timeout=10)

                    # Finally delete the space (and subsequently the access methods)
                    req_url = self.__url_api_cospaces + '/' + space_id
                    session.delete(req_url, verify=False, timeout=10)

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

        session = requests.session()
        session.auth = self.get_username(), self.get_password()

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
                resp = session.put(req_url, verify=self.__ssl_is_valid, data=properties, timeout=10)
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

        session = requests.session()
        session.auth = self.get_username(), self.get_password()

        req_url = self.__url_api_cospaces + '/' + space_id + '/accessmethods/' + am_id
        try:
            resp = session.delete(req_url, verify=self.__ssl_is_valid, timeout=10)
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
        session = requests.session()
        session.auth = self.get_username(), self.get_password()

        req_url = self.__url_api_cospaces + '?filter=' + str(query)

        if limit != None:
            req_url += '&limit=' + str(limit)
        if offset != None:
            req_url += '&offset=' + str(offset)

        try:
            resp = session.get(req_url, verify=self.__ssl_is_valid, timeout=10)
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
        """
    
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

    def get_leg(self, leg_id):
        """Get specific call leg details

        Args:
            leg_id (str): the call leg id

        Returns:
        """

    def mod_leg(self, leg_id):
        """Modify an active call leg

        Args:
            leg_id (str): the call leg id

        Returns:
        """
    def get_licensing(self):
        """Get CMS multipartyLicensing details

        Returns:
            dict: dict of license properties
        """

        session = requests.session()
        session.auth = self.get_username(), self.get_password()

        try:
            resp = session.get(self.__url_api_mlic, verify=self.__ssl_is_valid, timeout=10)
        except Exception as err:
            return err

        xml_resp = xmltodict.parse(resp.text)['multipartyLicensing']
        # Convert time_stamp str to datetime object for correct insertion into MongoDB
        xml_resp['timestamp'] = datetime.datetime.strptime(
            xml_resp['timestamp'], '%Y-%m-%dT%H:%M:%SZ')

        return xml_resp