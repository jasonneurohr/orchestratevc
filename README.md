# orchestratevc

**Under Development!**

This repository is broken up into four areas

* **orchestratevc** - the python classes for interacting with various videoconferencing devices
* **orchestratevc_api** - the EVE API which is used as the middleware between MongoDB and the reporting classes
* **orchestratevc_reporting** - the python classes for interacting with MongoDB through the EVE API
* **orchestratevc_portal** - user friendly interface for interacting with the MongoDB data via the API container

All output where the intention is storage for later analysis from the orchestratevc classes is intended to be stored in a **MongoDB** database called '**reporting**'

Collections inside the **reporting** database should be created as:

* **cdr_cisco_tps** - TPS CDR records
* **cdr_cisco_isdn** - ISDN GW CDR records
* **util_cisco_conductor_tps** - TPS utilisation data where integrated with the Cisco TelePresence Conductor (Remote Managed)
* **util_cisco_local_tps** - TPS utilisation data where not integrated with Cisco TelePresence Conductor (Locally Managed)
* **util_cisco_isdn** - ISDN GW channel utilisation data
* **util_cisco_expressway_license** - Cisco Expressway license utilisation data (and Video Communications Server, VCS)

There are several scripts within the docker db folder to take care of setting up MongoDB and also for populating dummy data for testing.

The orchestratevc python classes can be used in isolation or, all components can be spun up together using docker to provide a wholistic reporting solution.