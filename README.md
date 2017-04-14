# Varnish 5.0 automated build

## environment variables

make sure you have set up of the following environment variables on the control panel.

- VARNISHD_PARAMS=-s malloc,128M
- VARNISH_BACKEND=1.2.3.4:80;2.4.6.8:80
- VARNISH_FRONT=0.0.0.0:80
- VARNISH_CACHE_LIMIT=64M
- VARNISH_CNF=
- TCPROXY=0.0.0.0:443 -> 1.2.3.4:443

## startup varnish script
/usr/bin/supervisord
