FROM ubuntu:16.04
RUN apt-get update \ 
&& apt-get install -y \
    python3 \
    wget \
    git \
&& wget https://bootstrap.pypa.io/get-pip.py \ 
&& python3.5 get-pip.py \
&& pip3.5 install eve

CMD python3.5 /orchestratevc/orchestratevc_api/orchestratevc_api.py
