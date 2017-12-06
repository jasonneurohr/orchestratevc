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