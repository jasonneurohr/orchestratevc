import json
import requests
import datetime

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
    
    def end_session(self):
        self.__session.close()

    def safe_restart(self):
        try:
            response = self.__session.post(
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
        try:
            response = self.__session.get(
                "https://" + self.get_address() + "/api/v1/mgmt/network/info",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )
        
            response_dict = json.loads(response.text)

        except (requests.ConnectTimeout) as e:
            return "Connection timeout"

    def device_info(self):
        try:
            response = self.__session.get(
                "https://" + self.get_address() + "/api/v1/mgmt/device/info",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )
        
            response_dict = json.loads(response.text)
        
        except (requests.ConnectTimeout) as e:
            return "Connection timeout"

    def line_info(self):
        try:
            response = self.__session.get(
                "https://" + self.get_address() + "/api/v1/mgmt/lineInfo",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )
        
            response_dict = json.loads(response.text)

        except (requests.ConnectTimeout) as e:
            return "Connection timeout"

    def network_stats(self):
        try:
            response = self.__session.get(
                "https://" + self.get_address() + "/api/v1/mgmt/network/stats",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )
        
            response_dict = json.loads(response.text)

        except (requests.ConnectTimeout) as e:
            return "Connection timeout"
    
    def get_config(self, config_params=[]):
        # Example POST Data
        # {"data":["tcpIpApp.sntp.gmtOffset","tcpIpApp.sntp.daylightSavings.enable"]}
        data = json.dumps({"data": config_params}) # Create JSON structure

        try:
            response = self.__session.post(
                "https://" + self.get_address() + "/api/v1/mgmt/config/get",
                headers={"Content-Type": "application/json"},
                data=data,
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )

            # TODO
            try:
                return response.json()["data"]
            except Exception as e:
                return "-1"

        except (requests.exceptions.RequestException) as e:
            return "-1"
    
    def set_config(self, config_params={}):
        # Example POST Data
        # {"data":{"tcpIpApp.sntp.gmtOffset": "1.1.1.1")}
        data = json.dumps({"data": config_params}) # Create JSON structure

        try:
            response = self.__session.post(
                "https://" + self.get_address() + "/api/v1/mgmt/config/set",
                headers={"Content-Type": "application/json"},
                data=data,
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )

            # {"Status": "2000"} Indicates the request was successful
            if json.loads(response.text)["Status"] == "2000":
                return "1"
            else:
                return json.loads(response.text)["Status"] # Return the response from the Trio if not 2000

        except (requests.exceptions.RequestException) as e:
            return "-1"

    def get_time(self):
        try:
            response = self.__session.get(
                "https://" + self.get_address() + "/api/v1/mgmt/network/stats",
                headers={"Content-Type": "application/json"},
                verify=False, # Most Trio deployments use self-signed certificates
                timeout=2
            )

            # The HTTP Header format is: Sun, 10 Dec 2017 18:17:41 GMT 
            # It is converted to ISO8601 format YYYY-MM-DDTHH:MM:SS (without microseconds)
            return datetime.datetime.strptime(response.headers["date"], "%a, %d %b %Y %H:%M:%S %Z").isoformat()

        except (requests.exceptions.RequestException) as e:
            return "-1"