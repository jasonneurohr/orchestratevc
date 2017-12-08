import json
import requests

class PolycomTrio:

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

    def safe_restart(self):
        # session = requests.session()
        # session.auth = self.get_username(), self.get_password()

        try:
            response = session.post(
                "https://" + self.get_address() + "/api/v1/mgmt/safeRestart",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )

            # {"Status": "2000"} Indicates the request was successful,
            # and the Trio is rebooting.
            if json.loads(response.text)["Status"] == "2000":
                return "success"
            else:
                return response.text

        except (requests.ConnectTimeout) as e:
            return "Connection timeout"

    def network_info(self):
        session = requests.session()
        session.auth = self.get_username(), self.get_password()

        try:
            response = session.get(
                "https://" + self.get_address() + "/api/v1/mgmt/network/info",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )
        
            response_dict = json.loads(response.text)

        except (requests.ConnectTimeout) as e:
            return "Connection timeout"

    def device_info(self):
        session = requests.session()
        session.auth = self.get_username(), self.get_password()

        try:
            response = session.get(
                "https://" + self.get_address() + "/api/v1/mgmt/device/info",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )
        
            response_dict = json.loads(response.text)
        
        except (requests.ConnectTimeout) as e:
            return "Connection timeout"

    def line_info(self):
        session = requests.session()
        session.auth = self.get_username(), self.get_password()

        try:
            response = session.get(
                "https://" + self.get_address() + "/api/v1/mgmt/lineInfo",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )
        
            response_dict = json.loads(response.text)

        except (requests.ConnectTimeout) as e:
            return "Connection timeout"

    def network_stats(self):
        session = requests.session()
        session.auth = self.get_username(), self.get_password()

        try:
            response = session.get(
                "https://" + self.get_address() + "/api/v1/mgmt/network/stats",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )
        
            response_dict = json.loads(response.text)

        except (requests.ConnectTimeout) as e:
            return "Connection timeout"
    
    def get_config(self, config_params=[]):
        data = json.dumps({"data": config_params}) # Create JSON structure
        session = requests.session()
        session.auth = self.get_username(), self.get_password()

        try:
            response = session.post(
                "https://" + self.get_address() + "/api/v1/mgmt/config/get",
                headers={"Content-Type": "application/json"},
                data=data,
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )
        
            return response.json()

        except (requests.ConnectTimeout) as e:
            return "Connection timeout"

    def get_time(self):
        session = requests.session()
        session.auth = self.get_username(), self.get_password()

        try:
            response = session.get(
                "https://" + self.get_address() + "/api/v1/mgmt/network/stats",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )
        
            return response.headers

        except (requests.ConnectTimeout) as e:
            return "Connection timeout"