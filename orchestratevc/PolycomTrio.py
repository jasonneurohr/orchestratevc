import json
import requests

class PolycomTrio:

    def __init__(self, address, username, password):
        self.__address = str(address)
        self.__username = str(username)
        self.__password = str(password)
    
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
        session = requests.session()
        session.auth = self.get_username(), self.get_password()

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
