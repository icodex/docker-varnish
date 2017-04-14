if ( req.url ~ "(?i)(phpmyadmin|status|munin|server-status|feed|get)"||req.url ~ "(install|uninstall|upgrade|cron)(/|.*\.(php|php4|php5|cgi|pl|perl|jsp|asp|aspx|ashx))"||req.url ~ "sitemap.xml($|\.gz$)" ) { return (pipe); }

