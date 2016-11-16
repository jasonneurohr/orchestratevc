FROM ubuntu:16.04
COPY ./createUser.js /tmp/
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927 \
&& echo "deb http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.2 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-3.2.list \
&& apt-get update \ 
&& apt-get install -y mongodb-org \
&& mkdir /data \
&& mkdir /data/db 

COPY ./createUser.js /tmp/




CMD mongod --auth --port 27017 --dbpath /data/db
