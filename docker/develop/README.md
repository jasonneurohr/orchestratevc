Update the password variables in db/createUser.js where required.
Update the reporting user password in ../orchestratevc_api/settings.py

1. docker-compose build
2. docker-compose up -d
3. docker exec -it develop_db_1 /bin/bash -c "mongo < /tmp/createUser.js"
4. docker exec -it develop_db_1 /bin/bash -c "mongo < /tmp/dummyData.js"