import requests
import xmltodict
import datetime

class CallControl:
    """General VC CallControl superclass.
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

class Expressway(CallControl):
    """Expressway Subclass
    """

    def __init__(self, api_host, api_user, api_pass, api_port='443'):
        """Initialise an Expressway object
        Call the superclass's __init__ method and pass the required
        arguments.

        self.__ssl_is_valid will call the valid_certificate(self) method,
        to determine whether the Expressway certificate is valid.

        Args:
            __api_host (str): IP address or resolvable name of the device.
            __api_port (str): TCP port where the API/XML is accessible.
                Defaults to port 443
            __api_user (str): Username to access the device.
            __api_pass (str): Password to access the device.
        """

        CallControl.__init__(self, api_host, api_user, api_pass, api_port)

        self.__url_status = "https://{api_host}:{api_port}/status.xml".format(
            api_host=self.get_api_host(),
            api_port=self.get_api_port()
        )

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

    def get_status_xml(self):
        """Get Expressway status.xml

        """
        # TODO
        ns = {'ns': 'http://www.tandberg.no/XML/CUIL/1.0'}

        s = requests.session()
        s.auth = self.get_api_user(), self.get_api_pass()

        try:
            resp = s.get(self.__url_status, verify=self.__ssl_is_valid, timeout=10)
        except Exception as err:
            return err
