import json
import requests
import zeep
import logging.config


class CiscoUcmAxl:
    """CiscoUcmAxl defines methods for interacting with the Cisco Unified
    Communications Manager AXL interface.
    """

    def __init__(self, address, username, password, wsdl):
        self.__address = str(address)       # The CUCM address IP or FQDN
        self.__username = str(username)     # CUCM User with AXL permissions
        self.__password = str(password)
        # self.__wsdl = "file://" + wsdl      # The WSDL file (downloaded from CUCM)
        self.__wsdl = wsdl
        
        # Setup Requests session
        self.__session = requests.session()
        self.__session.auth = requests.auth.HTTPBasicAuth(self.get_username(), self.get_password())
        self.__session.verify = False

        # Setup the zeep transport
        self.__transport = zeep.Transport(session=self.__session)

        # Initalise a zeep client
        self.__client = zeep.Client(
            self.__wsdl,
            transport=self.__transport)
        
        # Initialise a zeep service
        self.__service = self.__client.create_service(
            "{http://www.cisco.com/AXLAPIService/}AXLAPIBinding",
            "https://" + self.__address + "/axl/")

    def __str__(self):
        return json.dumps({
            "address": self.__address,
            "username": self.__username,
            "password": self.__password
        })
    
    def enable_debug(self):
        """Enable zeep logging
        """

        logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'verbose': {
                'format': '%(name)s: %(message)s'
            }
        },
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'zeep.transports': {
                'level': 'DEBUG',
                'propagate': True,
                'handlers': ['console'],
            },
        }
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

    def get_phone(self, name):
        return self.__service.getPhone(name=name)

    def get_phones(self):
        return self.__service.listPhone(
            searchCriteria="%",
            returnedTags="Phone",)

    def get_osversion(self):
        return self.__service.getOSVersion()
