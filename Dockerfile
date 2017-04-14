FROM ubuntu:16.04
MAINTAINER Shing Lau "shing@evlit.com"

RUN apt-get -y update
RUN apt-get autoremove -y
RUN apt-get -fy install
RUN apt-get install -y build-essential gcc g++ make git autoconf automake re2c wget cron bzip2 libzip-dev libc6-dev file rcconf flex vim nano bison m4 gawk less make cpp binutils diffutils unzip tar bzip2 python-docutils automake autotools-dev libedit-dev libjemalloc-dev libncurses-dev libpcre3-dev libtool pkg-config python-docutils python-sphinx graphviz
RUN apt-get install -y supervisor
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

RUN cp /docker/supervisord.conf /etc/supervisor/supervisord.conf

ENV VARNISH_CNF ""
ENV VARNISH_BACKEND "1.2.3.4:80;2.4.6.8:80"
ENV VARNISH_FRONT "0.0.0.0:80"
ENV VARNISHD_PARAMS "-s malloc,128M"
ENV VARNISH_CACHE_LIMIT "64M"
ENV TCPROXY "0.0.0.0:443 -> 1.2.3.4:443"

EXPOSE 80

CMD ["/usr/bin/supervisord"]
