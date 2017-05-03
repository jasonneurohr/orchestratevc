
import requests
import xmltodict


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
    """Cisco CMS subclass
    """

    def __init__(self, api_host, api_user, api_pass, api_port='443'):
        """Initialise a Cms object
        Call the superclass's __init__ method and pass the required
        arguments.

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
        self.__url_api_calls = self.__url_api + 'calls'
        self.__url_api_cospaces = self.__url_api + 'cospaces'

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
        """
        """

        accessmethod_ids = []
        req_url = self.__url_api_cospaces + '/' + space_id + "/accessmethods/"
        api_session = requests.session()
        api_session.auth = self.get_api_user(), self.get_api_pass()
        api_response_accessmethods = api_session.get(req_url, verify=False, timeout=10)
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

    def get_total_conferences(self):
        """
        """

        api_session = requests.session()
        api_session.auth = self.get_api_user(), self.get_api_pass()
        api_response_conferences = api_session.get(self.__url_api_calls, verify=False, timeout=10)
        xml_api_response = xmltodict.parse(api_response_conferences.text)

        try:
            total_conferences = xml_api_response['calls']['@total']
        except:
            return 0

        return int(total_conferences)

    def set_all_calllegprofile_properties(self, properties={}):
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

class tps(Bridges):
    """
    """

    def __init__(self, api_host, api_user, api_pass, api_port='443'):
        """
        """

        bridges.__init__(self, api_host, api_port, api_user, api_pass)

