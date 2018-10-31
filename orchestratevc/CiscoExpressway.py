import json
import requests
import datetime

class CiscoExpressway:

    def __init__(self, address, username, password):
        self.__address = str(address)
        self.__username = str(username)
        self.__password = str(password)
        self.__session = requests.session()
        self.__session.auth = self.get_username(), self.get_password()
    
    def __str__(self):
        return json.dumps({
            "address": self.__address, 
            "username": self.__username, 
            "password": self.__password
        })
    
    def get_address(self):
        return self.__address

    def set_address(self, address):
        self.__address = str(address)

    def get_username(self):
        return self.__username

    def set_username(self, username):
        self.__username = str(username)

    def get_password(self):
        return self.__password

    def set_password(self, password):
        self.__password = password
    
    def end_session(self):
        self.__session.close()

    def __get_req(self, url):
        try:
            response = self.__session.get(
                url,
                verify=False,
                timeout=5)

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as err:
            print(err)
            raise

        return response

    def __post_req(self, url, properties=None):
        print("Postreq data: ", properties)
        try:
            response = self.__session.post(
                url,
                verify=False,
                data=properties,
                headers={"Content-Type":"application/json"},
                timeout=5)

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as err:
            print(err)
            raise

        return response

    def __put_req(self, url, properties=None):
        print("Putreq data: ", properties)
        try:
            response = self.__session.put(
                url,
                verify=False,
                data=properties,
                headers={"Content-Type":"application/json"},
                timeout=5)

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as err:
            print(err)
            raise

        return response
    
    def __delete_req(self, url, properties=None):
        try:
            response = self.__session.delete(
                url,
                verify=False,
                data=properties,
                timeout=5)

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as err:
            print(err)
            raise

        return response
    
    def get_dns(self):
        """READ DNS configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/dns/dns"
        print(self.get_username(), self.get_password())
        return self.__get_req(url).text

    def mod_dns(self, properties=None):
        """UPDATE DNS configuration

        DNSRequestsPortRange
        DNSRequestsPortRangeEnd
        DNSRequestsPortRangeStart
        DomainName
        SystemHostName

        Args:
            properties (dict): Dictionary of properties

        Returns:
            str: The API response string
        """

        url = "https://" + self.__address + "/api/provisioning/common/dns/dns"
        return self.__put_req(url, json.dumps(properties)).text

    def new_dnsserver(self):
        #TODO : API doesn't appear to work correctly
        """CREATE a new DNS server
        """
        data=None
        url = "https://" + self.__address + "/api/provisioning/common/dns/dnsserver"
        return self.__post_req(url, json.dumps(data)).text

    def get_dnsserver(self, properties=None):
        """READ DNS server configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/dns/dnsserver"
        self.__get_req(url)

    def new_domain(self, properties=None):
        """CREATE DNS domain
        """

        url = "https://" + self.__address + "/api/provisioning/common/dns/domain"
        self.__post_req(url, properties)

    def get_domain(self, properties=None):
        """READ DNS domain
        """

        url = "https://" + self.__address + "/api/provisioning/common/dns/domain"
        self.__get_req(url)

    def mod_mra(self, properties=None):
        """UPDATE MRA configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/mra"
        self.__put_req(url, properties)

    def get_mra(self):
        """READ MRA configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/mra"
        self.__get_req(url)

    def mod_sip(self, properties=None):
        """UPDATE SIP configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/protocol/sip/configuration"
        self.__put_req(url, json.dumps(properties))

    def get_sip(self):
        """READ SIP configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/protocol/sip"
        self.__get_req(url)

    def mod_qos(self, properties=None):
        """UPDATE QoS configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/qos"
        self.__put_req(url, json.dumps(properties))

    def get_qos(self):
        """READ QoS configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/qos"
        self.__get_req(url)

    def new_searchrule(self, properties=None):
        """CREATE search rule

        Required:
            Priority
            Name
            TargetName
        """

        url = "https://" + self.__address + "/api/provisioning/common/searchrule"
        return self.__post_req(url, json.dumps(properties)).text

    def get_searchrule(self):
        """READ search rule
        """

        url = "https://" + self.__address + "/api/provisioning/common/searchrule"
        self.__get_req(url)

    def mod_searchrule(self, properties=None):
        """UPDATE search rule
        """

        url = "https://" + self.__address + "/api/provisioning/common/searchrule"
        self.__put_req(url, json.dumps(properties))
    
    def del_searchrule(self, properties=None):
        """DELETE search rule
        """

        url = "https://" + self.__address + "/api/provisioning/common/searchrule"
        self.__delete_req(url, properties)

    def get_ntpserver(self):
        """READ NTP server configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/time/ntpserver"
        self.__get_req(url)

    def new_ntpserver(self, properties=None):
        """CREATE NTP server
        """

        url = "https://" + self.__address + "/api/provisioning/common/time/ntpserver"
        self.__post_req(url, json.dumps(properties))
    
    def mod_ntpserver(self, properties=None):
        """UPDATE NTP server
        """

        url = "https://" + self.__address + "/api/provisioning/common/time/ntpserver"
        self.__put_req(url, properties)

    def del_ntpserver(self, properties=None):
        """DELETE NTP server
        """

        url = "https://" + self.__address + "/api/provisioning/common/time/ntpserver"
        self.__delete_req(url, properties)
    
    def get_ntpstatus(self):
        """READ NTP status
        """

        url = "https://" + self.__address + "/api/provisioning/common/time/status"
        self.__get_req(url)

    def get_timezone(self):
        """READ timezone configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/time/timezone"
        self.__get_req(url)

    def mod_timezone(self, properties=None):
        """UPDATE timezone configuration
        """

        url = "https://" + self.__address + "/api/provisioning/common/time/timezone"
        self.__put_req(url, properties)

    def get_transform(self):
        """READ transform
        """

        url = "https://" + self.__address + "/api/provisioning/common/transform"
        self.__get_req(url)

    def new_transform(self, properties=None):
        """CREATE transform
        """

        url = "https://" + self.__address + "/api/provisioning/common/transform"
        self.__post_req(url, properties)

    def mod_transform(self, properties=None):
        """UPDATE transform
        """

        url = "https://" + self.__address + "/api/provisioning/common/transform"
        self.__put_req(url, properties)

    def del_transform(self, properties=None):
        """DELETE transform
        """

        url = "https://" + self.__address + "/api/provisioning/common/transform"
        self.__delete_req(url, properties)

    def get_neighborzone(self):
        """READ neighorzone
        """

        url = "https://" + self.__address + "/api/provisioning/common/zone/neighborzone"
        self.__get_req(url)

    def new_neighborzone(self, properties=None):
        """CREATE neighborzone
        """

        url = "https://" + self.__address + "/api/provisioning/common/zone/neighborzone"
        self.__post_req(url, json.dumps(properties))
    
    def mod_neighborzone(self, properties=None):
        """UPDATE neighborzone
        """

        url = "https://" + self.__address + "/api/provisioning/common/zone/neighborzone"
        self.__put_req(url, properties)

    def del_neighborzone(self, properties=None):
        """DELETE neighborzone
        """

        url = "https://" + self.__address + "/api/provisioning/common/zone/neighborzone"
        self.__delete_req(url, properties)

    def get_cucmserver(self):
        """GET CUCM server configuration
        """

        url = "https://" + self.__address + "/api/provisioning/controller/server/cucm"
        self.__get_req(url)

    def new_cucmserver(self, properties=None):
        """CREATE CUCM server configuration
        """

        url = "https://" + self.__address + "/api/provisioning/controller/server/cucm"
        self.__post_req(url, properties)

    def del_cucmserver(self, properties=None):
        """DELETE CUCM server configuration
        """

        url = "https://" + self.__address + "/api/provisioning/controller/server/cucm"
        self.__delete_req(url, properties)

    def get_zone_traversalclient(self):
        """READ traversalclient zone
        """

        url = "https://" + self.__address + "/api/provisioning/controller/zone/traversalclient"
        self.__get_req(url)

    def new_zone_traversalclient(self, properties=None):
        """CREATE traversalclient zone
        """

        url = "https://" + self.__address + "/api/provisioning/controller/zone/traversalclient"
        self.__post_req(url, json.dumps(properties))

    def mod_zone_traversalclient(self, properties=None):
        """UPDATE traversalclient zone
        """

        url = "https://" + self.__address + "/api/provisioning/controller/zone/traversalclient"
        self.__put_req(url, json.dumps(properties))

    def del_zone_traversalclient(self, properties=None):
        """DELETE traversaclient zone
        """

        url = "https://" + self.__address + "/api/provisioning/controller/zone/traversalclient"
        self.__delete_req(url, properties)

    def get_turn(self):
        """READ TURN configuration
        """

        url = "https://" + self.__address + "/api/provisioning/edge/traversal/turn"
        self.__get_req(url)

    def mod_turn(self, properties=None):
        """UPDATE TURN configuration
        """

        url = "https://" + self.__address + "/api/provisioning/edge/traversal/turn"
        self.__put_req(url, properties)

    def get_zone_traversalserver(self):
        """READ traversalserver zone configuration
        """

        url = "https://" + self.__address + "/api/provisioning/edge/zone/traversalserver"
        self.__get_req(url)

    def new_zone_traversalserver(self, properties=None):
        """CREATE traversalserver zone
        """

        url = "https://" + self.__address + "/api/provisioning/edge/zone/traversalserver"
        self.__post_req(url, properties)

    def mod_zone_traversalserver(self, properties=None):
        """UPDATE traversalserver zone configuration
        """

        url = "https://" + self.__address + "/api/provisioning/edge/zone/traversalserver"
        self.__put_req(url, properties)

    def del_zone_traversalserver(self, properties=None):
        """DELETE traversalserver zone
        """

        url = "https://" + self.__address + "/api/provisioning/edge/zone/traversalserver"
        self.__delete_req(url, properties)

    def get_uczone_traversalclient(self):
        """READ traversalclient zone
        """

        url = "https://" + self.__address + "/api/provisioning/controller/zone/unifiedcommunicationstraversal"
        self.__get_req(url)

    def new_uczone_traversalclient(self, properties=None):
        """CREATE traversalclient zone
        """

        url = "https://" + self.__address + "/api/provisioning/controller/zone/unifiedcommunicationstraversal"
        self.__post_req(url, json.dumps(properties))

    def mod_uczone_traversalclient(self, properties=None):
        """UPDATE traversalclient zone
        """

        url = "https://" + self.__address + "/api/provisioning/controller/zone/unifiedcommunicationstraversal"
        self.__put_req(url, json.dumps(properties))

    def del_uczone_traversalclient(self, properties=None):
        """DELETE traversaclient zone
        """

        url = "https://" + self.__address + "/api/provisioning/controller/zone/unifiedcommunicationstraversal"
        self.__delete_req(url, properties)

    def get_optionkey(self):
        """READ option keys
        """

        url = "https://" + self.__address + "/api/provisioning/optionkey"
        self.__get_req(url)

    def new_optionkey(self, properties=None):
        """CREATE option key
        """

        url = "https://" + self.__address + "/api/provisioning/optionkey"
        self.__post_req(url, properties)

    def del_optionkey(self, properties=None):
        """DELETE option key
        """

        url = "https://" + self.__address + "/api/provisioning/optionkey"
        self.__delete_req(url, properties)