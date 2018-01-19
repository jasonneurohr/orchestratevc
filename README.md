# orchestratevc

**Under Development!**

* **orchestratevc** - the python classes for interacting with various videoconferencing devices

All output where the intention is storage for later analysis from the orchestratevc classes is intended to be stored in a **MongoDB** database called '**reporting**'

Collections inside the **reporting** database should be created as:

* **cdr_cisco_tps** - TPS CDR records
* **cdr_cisco_isdn** - ISDN GW CDR records
* **util_cisco_conductor_tps** - TPS utilisation data where integrated with the Cisco TelePresence Conductor (Remote Managed)
* **util_cisco_local_tps** - TPS utilisation data where not integrated with Cisco TelePresence Conductor (Locally Managed)
* **util_cisco_isdn** - ISDN GW channel utilisation data
* **util_cisco_expressway_license** - Cisco Expressway license utilisation data (and Video Communications Server, VCS)

There are several scripts within the docker db folder to take care of setting up MongoDB and also for populating dummy data for testing.

# CiscoUCMAxl

Example SOAP Request

Headers:
Authorization: Basic XXXX
SOAPAction: CUCM:DB ver=10.5 listRoutePattern
Content-Type: text/xml

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://www.cisco.com/AXL/API/10.5">
    <soapenv:Header/>
    <soapenv:Body>
        <ns:listRoutePattern>
        	<searchCriteria>
        		<pattern>%</pattern>
        	</searchCriteria>
        	<returnedTags>
        		<LRoutePattern></LRoutePattern>
        	</returnedTags>
        </ns:listRoutePattern>
    </soapenv:Body>
</soapenv:Envelope>
```

# CiscoUcmRis

References
* https://d1nmyq4gcgsfi5.cloudfront.net/site/sxml/documents/api-reference/risport/#StateInfoUsage

# Polycom Trio

## Setting *device.x* Configuration Parameters

When utilising the set_config method with device.x configuration parameters you must also add the following to the JSON POST data (the dictionary being passed to the method), **"device.set":"1"** and **"device.*configparam*.set:"1"**. 

See the following example to modify the provisioning server type (to http) and name.

```json
{
	"data": {
		"device.set": "1",
		"device.prov.serverType.set": "1",
		"device.prov.serverType": "2",
		"device.prov.serverName.set": "1",
		"device.prov.serverName": "http://1.1.1.1"
	}
}
```