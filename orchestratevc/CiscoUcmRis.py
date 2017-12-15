import json
import requests
import zeep
import logging


class CiscoUcmRis:
    """CiscoUcmRis defines methods for interacting with the Cisco Unified
    Communications Manager RIS interface.
    """

    def __init__(self, address, username, password, wsdl):
        self.__address = str(address)       # The CUCM address IP or FQDN
        self.__username = str(username)     # CUCM User with AXL permissions
        self.__password = str(password)
        self.__wsdl = "file://" + wsdl      # The WSDL file (downloaded from CUCM)
        
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
            "{http://schemas.cisco.com/ast/soap}RisBinding",
            "https://" + self.__address + "/realtimeservice2/services/RISService70")

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

    def get_devices(self):
        return self.__service.selectCmDevice(
            StateInfo="",
            CmSelectionCriteria={
                "MaxReturnedDevices":"1000",
                "DeviceClass":"Any",
                "Model": "255",
                "Status": "Any",
                "NodeName":"",
                "SelectBy":"DirNumber",
                "SelectItems":{
                    "item":"*"
                },
                "Protocol": "Any",
                "DownloadStatus": "Any"
            }
        )

    def get_phone_iplist(self):
        sentinal = 0
        devices = {}
        
        # Get all devices
        response = self.get_devices()

        # Loop through response and build dict of devices
        while sentinal < response["SelectCmDeviceResult"]["TotalDevicesFound"]:
            devices[response["SelectCmDeviceResult"]["CmNodes"]["item"][0]["CmDevices"]["item"][sentinal]["Name"]] = response["SelectCmDeviceResult"]["CmNodes"]["item"][0]["CmDevices"]["item"][0]["IPAddress"]["item"][0]["IP"]
            sentinal += 1

        return devices
            