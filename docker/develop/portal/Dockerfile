FROM ubuntu:16.04
RUN apt-get update \ 
&& apt-get install -y \
    apache2 \
    git 

ADD 000-default.conf /etc/apache2/sites-enabled/000-default.conf

CMD /usr/sbin/apache2ctl -D FOREGROUND
