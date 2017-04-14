FROM ubuntu:16.04
MAINTAINER Shing Lau "shing@evlit.com"

RUN yum -y update
RUN apt-get install -y python-docutils automake autotools-dev libedit-dev libjemalloc-dev libncurses-dev libpcre3-dev libtool pkg-config python-docutils python-sphinx graphviz
RUN cd /tmp
RUN wget https://repo.varnish-cache.org/pkg/5.0.0/varnish_5.0.0-1_amd64.deb
RUN wget https://repo.varnish-cache.org/pkg/5.0.0/varnish-dev_5.0.0-1_amd64.deb
RUN dpkg -i varnish_5.0.0-1_amd64.deb
RUN dpkg -i varnish-dev_5.0.0-1_amd64.deb
RUN apt-get -f -y install
RUN dpkg -i varnish_5.0.0-1_amd64.deb
RUN dpkg -i varnish-dev_5.0.0-1_amd64.deb

ADD . /docker/
RUN chmod +x /docker/bin/*
RUN ls -lh /docker
RUN ln -sf /docker/bin/tcproxy.bin /usr/local/sbin/tcproxy

RUN cp /docker/supervisord.ini /etc/supervisord.d/supervisord.ini

ENV VARNISH_CNF ""
ENV VARNISH_BACKEND "1.2.3.4:80;2.4.6.8:80"
ENV VARNISH_FRONT "0.0.0.0:80"
ENV VARNISHD_PARAMS "-s malloc,128M"
ENV VARNISH_CACHE_LIMIT "64M"
ENV TCPROXY "0.0.0.0:443 -> 1.2.3.4:443"

EXPOSE 80

CMD ["/usr/bin/supervisord"]