###################################################
# Written by iCodex. -  http://icodex.org         #
###################################################

vcl 4.0;
import std;
import directors;

# Setup the backend servers
include "/etc/varnish/backends.vcl";

# Setup the different backends logic
include "/etc/varnish/acllogic.vcl";

sub vcl_init {
    # Setup the dynamic backend servers
    include "/etc/varnish/backend_directors.vcl";

    return (ok);
}

#######################################################################
# Client side

sub vcl_recv {
    # Include custom vcl_recv logic
    include "/etc/varnish/vhosts.vcl";

    #set req.http.grace = "none";

    call identify_device;

    unset req.http.proxy;

    # Bypass
    if (client.ip ~ node) {
      set req.hash_always_miss = true;
      return (pipe);
    }

    if (!std.healthy(req.backend_hint)) {
      unset req.http.Cookie;
    }

    set req.hash_ignore_busy = true;

    if (client.ip ~ denyip) {
      #return (synth(720, "http://www.google.com"));
    }

    # shortcut for DFind requests
    if (req.url ~ "^/w00tw00t") {
      return (synth(404, "Not Found"));
    }

    if (req.restarts == 0) {
      if (req.http.X-Forwarded-For) {
        set req.http.X-Forwarded-For = regsub(req.http.X-Forwarded-For, "[, ].*$", "");
      } elsif (req.http.Cf-Connecting-Ip) {
        set req.http.X-Forwarded-For = regsub(req.http.Cf-Connecting-Ip, "[, ].*$", "");
      } elsif (req.http.Incap-Client-Ip) {
        set req.http.X-Forwarded-For = regsub(req.http.Incap-Client-Ip, "[, ].*$", "");
      } elsif (req.http.Cdn-Src-Ip) {
        set req.http.X-Forwarded-For = regsub(req.http.Cdn-Src-Ip, "[, ].*$", "");
      } else {
        set req.http.X-Forwarded-For = regsub(client.ip, "[, ].*$", "");
        set req.http.Cf-Connecting-Ip = regsub(client.ip, "[, ].*$", "");
        set req.http.Incap-Client-Ip = regsub(client.ip, "[, ].*$", "");
        set req.http.Cdn-Src-Ip = regsub(client.ip, "[, ].*$", "");
        std.collect(req.http.X-Forwarded-For);
      }
    }

    if (req.http.X-NginX-Ssl == "true" ) {
      set req.http.X-Forwarded-Proto = "https";
      set req.http.X-Forwarded-Port = "443";
    }

    # Normalize the header, remove the port (in case you're testing this on various TCP ports)
    set req.http.Host = regsub(req.http.host, ":[0-9]+", "");

    # Normalize the query arguments
    #set req.url = std.querysort(req.url);

    # Allow purging
    if (req.method == "PURGE") {
      if (!client.ip ~ trusted) {
        #return (synth(405, "Not Allowed"));
      }
      return (purge);
    }

    if (req.method == "BAN") {
      # Same ACL check as above:
      if (!client.ip ~ trusted) {
        #return (synth(405, "Not Allowed."));
      }
      ban("req.http.host == " + req.http.host +
            " && req.url == " + req.url);

      # Throw a synthetic page so the
      # request won't go to the backend.
      return(synth(200, "Ban added"));
     }

    if (req.method == "PRI") {
      /* We do not support SPDY or HTTP/2.0 */
      return (synth(405, "We do not support SPDY or HTTP/2.0"));
    }

    if (req.method != "GET" &&
      req.method != "HEAD" &&
      req.method != "PUT" &&
      req.method != "POST" &&
      req.method != "TRACE" &&
      req.method != "OPTIONS" &&
      req.method != "DELETE") {
        /* Non-RFC2616 or CONNECT which is weird. */
        return (pipe);
    }

    if (req.method == "POST" || req.method == "PUT") {
#        return(pipe);
        set req.http.x-method = req.method;
    }

    if (req.method != "GET" && req.method != "HEAD") {
        /* We only deal with GET and HEAD by default */
        set req.hash_always_miss = true;
        return (pass);
    }

    # For Websocket support, always pipe the requests: https://www.varnish-cache.org/docs/3.0/tutorial/websockets.html
    if (req.http.upgrade ~ "(?i)websocket") {
        return (pipe);
    }

    # Strip out Google Analytics campaign variables. They are only needed
    # by the javascript running on the page
    # utm_source, utm_medium, utm_campaign, gclid
    if (req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=") {
      set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
      set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
      set req.url = regsub(req.url, "\?&", "?");
      set req.url = regsub(req.url, "\?$", "");
    }

    # Strip hash, server doesn't need it.
    if (req.url ~ "\#") {
      set req.url = regsub(req.url, "\#.*$", "");
    }

    # Strip a trailing ? if it exists
    if (req.url ~ "\?$") {
      set req.url = regsub(req.url, "\?$", "");
    }

    # Some generic cookie manipulation, useful for all templates that follow
    # Remove the "has_js" cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "has_js=[^;]+(; )?", "");

    # Remove any Google Analytics based cookies
    set req.http.Cookie = regsuball(req.http.Cookie, "__utm.=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "_ga=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmctr=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmcmd.=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmccn.=[^;]+(; )?", "");

    # Remove DoubleClick offensive cookies
    set req.http.Cookie = regsuball(req.http.Cookie, "__gads=[^;]+(; )?", "");

    # Remove Cloudflare cookies
    set req.http.Cookie = regsuball(req.http.Cookie, "__cfduid=[^;]+(; )?", "");

    # Remove the Quant Capital cookies (added by some plugin, all __qca)
    set req.http.Cookie = regsuball(req.http.Cookie, "__qc.=[^;]+(; )?", "");

    # Remove the AddThis cookies
    set req.http.Cookie = regsuball(req.http.Cookie, "__atuv.=[^;]+(; )?", "");

    # Remove a ";" prefix in the cookie if present
    set req.http.Cookie = regsuball(req.http.Cookie, "^;\s*", "");

    # Are there cookies left with only spaces or that are empty?
    if (req.http.Cookie ~ "^\s*$") {
      unset req.http.Cookie;
    }

    # remove ?xxx=xxxxx strings from urls so css and js files are cached.
    set req.url = regsub(req.url, "\.js\?.*$", ".js");
    set req.url = regsub(req.url, "\.css\?.*$", ".css");
    set req.url = regsub(req.url, "\?ver=.*$", "");

    # fetch & deliver once we get the result
    if ( req.http.Pragma ~ "(?i)no-cache" ||
      req.http.Cache-Control ~ "(?i)max-age=0" ||
      req.http.Cache-Control ~ "(?i)no-cache") {
      # Ignore requests via proxy caches,  IE users and badly behaved crawlers
      # like msnbot that send no-cache with every request.
      if (!(req.http.Via ||
           req.http.User-Agent ~ "(?i)(bot|spider|search|MSIE|HostTracker)" ||
           req.http.X-Purge)) {
          return (purge);
      }
    }

    # Normalize Accept-Encoding header
    # straight from the manual: https://www.varnish-cache.org/docs/3.0/tutorial/vary.html
    # TODO: Test if it's still needed, Varnish 4 now does this by itself if http_gzip_support = on
    # https://www.varnish-cache.org/docs/trunk/users-guide/compression.html
    # https://www.varnish-cache.org/docs/trunk/phk/gzip.html
    if (req.http.Accept-Encoding) {
      # Do no compress compressed files...
      if (req.url ~ "^[^?]*\.(?i)(jpg|jpeg|webp|png|gif|bmp|gz|tgz|bz2|tbz|lzma|mp3|ogg|swf|ico)(\?.*)?$" || req.http.user-agent ~ "MSIE 6") {
        unset req.http.Accept-Encoding;
      } elsif (req.http.Accept-Encoding ~ "gzip") {
        set req.http.Accept-Encoding = "gzip";
      } elsif (req.http.Accept-Encoding ~ "deflate") {
        set req.http.Accept-Encoding = "deflate";
      } else {
        unset req.http.Accept-Encoding;
      }
    }

    # Large static files are delivered directly to the end-user without
    # waiting for Varnish to fully read the file first.
    # Varnish 4 fully supports Streaming, so set do_stream in vcl_backend_response()
    if (req.http.Content-Type ~ "(?i)(octet-stream)" || req.url ~ "^[^?]*\.(7z|avi|bz2|flac|flv|gz|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|ogm|opus|rar|tar|tgz|tbz|txz|wav|webm|xz|zip)(\?.*)?$") {
      unset req.http.Cookie;
      return (hash);
    }

    # Remove all cookies for static files
    # A valid discussion could be held on this line: do you really need to cache static files that don't cause load? Only if you have memory left.
    # Sure, there's disk I/O, but chances are your OS will already have these files in their buffers (thus memory).
    # Before you blindly enable this, have a read here: https://ma.ttias.be/stop-caching-static-files/
    if (req.url ~ "^[^?]*\.(?i)(bmp|bz2|css|doc|eot|flv|gif|gz|ico|jpeg|jpg|js|less|mp[34]|pdf|png|rar|rtf|swf|tar|tgz|txt|wav|woff|xml|zip|avi|deb|iso|img|dmg|mkv|pls|torrent)(\?.*)?$") {
      unset req.http.Cookie;
      return (hash);
    }

    if (req.url ~ "^[^?]*\.(?i)(xmlrpc.php|wlmanifest.xml)(\?.*)?$") {
      unset req.http.Cookie;
      return (hash);
    }

    # Send Surrogate-Capability headers to announce ESI support to backend
    set req.http.Surrogate-Capability = "key=ESI/1.0";

    if (req.http.Authorization ||
       req.http.Authenticate ||
       req.http.WWW-Authenticate ||
       req.http.X-Requested-With == "(?i)XMLHttpRequest") {
        /* Not cacheable by default */
        set req.hash_always_miss = true;
        return (pass);
    }

    #Dont cache ajax request
    if (req.url ~ "^.*/ajax/.*$" || req.url ~ "^.*/ahah/.*$") {
      set req.hash_always_miss = true;
      return (pass);
    }

    if (req.http.Cache-Control && req.http.Cache-Control ~ "(?i)private") {
      set req.hash_always_miss = true;
      return (pass);
    }

    if (req.url ~ "\.pagespeed\.([a-z]\.)?[a-z]{2}\.[^.]{10}\.[^.]+" || req.url ~ "\?nocache") {
      set req.hash_always_miss = true;
      return (pass);
    }

    if (req.url ~ "^[^?]*\.(?i)(asp|aspx|ashx|php|php4|php5|cgi|pl|perl|jsp|do)(\?.*)?$") {
      set req.hash_always_miss = true;
      return (pass);
    }

    return (hash);
}

sub vcl_pipe {
    # By default Connection: close is set on all piped requests, to stop
    # connection reuse from sending future requests directly to the
    # (potentially) wrong backend. If you do want this to happen, you can undo
    # it here.
    set bereq.http.Connection = "close";
    # Implementing websocket support (https://www.varnish-cache.org/docs/4.0/users-guide/vcl-example-websockets.html)
    if (req.http.Upgrade) {
      set bereq.http.Upgrade = req.http.Upgrade;
    }
    return (pipe);
}

sub vcl_pass {
    return (fetch);
}

sub vcl_hash {
    hash_data(req.url);
    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }

    # If the client supports compression, keep that in a different cache
    if (req.http.Accept-Encoding ~ "gzip") {
        hash_data("gzip");
    } elseif (req.http.Accept-Encoding ~ "deflate") {
        hash_data("deflate");
    }
    if (req.http.Accept-Encoding) {
      hash_data(req.http.Accept-Encoding);
    }

    # If the device has been classified as any sort of mobile device, include the User-Agent in the hash
    # However, do not do this for any static assets as our web application returns the same ones for every device.
    if (!(req.url ~ "^[^?]*\.(?i)(bmp|bz2|css|doc|eot|flv|gif|gz|ico|jpeg|jpg|js|less|mp[34]|mkv|pdf|png|rar|rtf|swf|tar|tgz|txt|wav|woff|xml|zip)(\?.*)?$")) {
      hash_data(req.http.X-UA-Device);
    }

    # hash cookies for requests that have them
    if (req.http.Cookie) {
      hash_data(req.http.Cookie);
    }
}

sub vcl_purge {
    # Only handle actual PURGE HTTP methods, everything else is discarded
    if (req.method != "PURGE") {
      # restart request
      set req.http.X-Purge = "Yes";
      return(restart);
    }
    return (synth(200, "Purged"));
}

sub vcl_hit {
    if (obj.ttl >= 0s) {
      # A pure unadultered hit, deliver it
      return (deliver);
    }
    # We have no fresh fish. Lets look at the stale ones.
    if (std.healthy(req.backend_hint)) {
    # Backend is healthy. Limit age to 10s.
      if (obj.ttl + 10s > 0s) {
        #set req.http.grace = "normal(limited)";
        return (deliver);
      } else {
        # No candidate for grace. Fetch a fresh object.
        return(miss);
      }
    } else {
    # backend is sick - use full grace
      if (obj.ttl + obj.grace > 0s) {
        #set req.http.grace = "full";
        return (deliver);
      } else {
        # no graced object.
        return (miss);
      }
    }

    return (miss);
}

sub vcl_miss {
    return (fetch);
}

sub vcl_deliver {
    #if (!client.ip ~ trusted) {
    #  set resp.http.grace = req.http.grace;
    #}

    #set resp.http.Node-Level = resp.http.X-Node-Level;
    unset resp.http.X-Node-Level;

    # From http://varnish-cache.org/wiki/VCLExampleLongerCaching
    if (resp.http.magicmarker) {
      /* Remove the magic marker */
      unset resp.http.magicmarker;

      /* By definition we have a fresh object */
      set resp.http.Age = "0";
      set resp.http.Expires = "-1";
    }

    # Always send this instead of using meta tags in markup
    if (resp.http.Content-Type ~ "html") {
      set resp.http.X-UA-Compatible = "IE=edge,chrome=1";
    }

    # Change some headers
    unset resp.http.X-Drupal-Cache;
    unset resp.http.X-Page-Speed;
    unset resp.http.X-Powered-By;
    unset resp.http.X-AspNet-Version;
    unset resp.http.Link;
    unset resp.http.X-Generator;

    unset resp.http.Age;
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    #set resp.http.Via = "1.1 varnish-v4, 1.1 icodex";
    unset resp.http.X-Edge-Location;
    #set resp.http.X-Edge-Location = "HKG";
    unset resp.http.Server;
    set resp.http.Server = "CWS/2.0";
    unset resp.http.X-Via;

    set resp.http.X-Frame-Options = "SAMEORIGIN";
    set resp.http.X-Content-Type-Options = "nosniff";
    set resp.http.X-XSS-Protection = "1; mode=block";
    #set resp.http.Strict-Transport-Security= "max-age=31536000; includeSubDomains; preload";

    unset resp.http.Connection;
    #set resp.http.Connection = "Keep-Alive";
    #set resp.http.Keep-Alive = "timeout=60";

    if (obj.hits > 0) {
      set resp.http.X-Cache = "HIT";
    } else {
      set resp.http.X-Cache = "MISS";
    }

    # Please note that obj.hits behaviour changed in 4.0, now it counts per objecthead, not per object
    # and obj.hits may not be reset in some cases where bans are in use. See bug 1492 for details.
    # So take hits with a grain of salt
    #set resp.http.X-Cache-Hits = obj.hits;

    return (deliver);
}

/*
 * We can come here "invisibly" with the following errors: 413, 417 & 503
 */
sub vcl_synth {
    set resp.http.Content-Type = "text/html; charset=utf-8";
    set resp.http.Retry-After = "5";
    if (resp.status == 720) {
        # We use this special error status 720 to force redirects with 301 (permanent) redirects
        # To use this, call the following from anywhere in vcl_recv: error 720 "http://host/new.html"
        set resp.status = 301;
        set resp.http.Location = resp.reason;
        return (deliver);
    } elseif (resp.status == 721) {
        # And we use error status 721 to force redirects with a 302 (temporary) redirect
        # To use this, call the following from anywhere in vcl_recv: error 720 "http://host/new.html"
        set resp.status = 302;
        set resp.http.Location = resp.reason;
        return (deliver);
    }

    synthetic( {"
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
 "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
  <head>
    <title>"} + resp.status + " " + resp.reason + {"</title>
  </head>
  <body>
    <h1>Error "} + resp.status + " " + resp.reason + {"</h1>
    <p>"} + resp.reason + {"</p>
    <h3>Guru Meditation:</h3>
    <p>XID: "} + req.xid + {"</p>
    <hr>
    <p>Varnish Cache Server</p>
  </body>
</html>
"} );

    return (deliver);
}

#######################################################################
# Backend Fetch

sub vcl_backend_fetch {
    set bereq.method = bereq.http.x-method;
    if (bereq.method == "GET") {
      unset bereq.body;
    }
    return (fetch);
}

sub vcl_backend_response {
    set beresp.http.X-Node-Level = std.integer(beresp.http.Node-Level, 0) + 1;

    set beresp.ttl = std.duration(regsub(beresp.http.Cache-Control, ".*s-maxage=([0-9]+).*", "\1") + "s", 10m);

    # Pause ESI request and remove Surrogate-Control header
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
      unset beresp.http.Surrogate-Control;
      set beresp.do_gunzip = true;
      set beresp.do_esi = true;
    }

    if (bereq.url ~ "^[^?]*\.(?i)(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
      unset beresp.http.Set-Cookie;
    } elsif (bereq.url ~ "^[^?]*(/|\.(?i)(html|htm|shtml|shtm|txt|log|xml)(\?.*)?)$") {
      set beresp.do_esi = true;
    }

    if (beresp.http.Vary ~ "User-Agent") {
      set beresp.http.Vary = regsub(beresp.http.Vary, ",? *User-Agent *", "");
      set beresp.http.Vary = regsub(beresp.http.Vary, "^, *", "");
      if (beresp.http.Vary == "") {
        unset beresp.http.Vary;
      }
    }

    # Large static files are delivered directly to the end-user without
    # waiting for Varnish to fully read the file first.
    # Varnish 4 fully supports Streaming, so use streaming here to avoid locking.
    # do not cache files > 128 MiB
    if (std.integer(beresp.http.Content-Length,0) > 134217728 || std.integer(beresp.http.Content-Length,0) < 0) {
      unset beresp.http.Set-Cookie;
      set beresp.ttl = 0s;
      set beresp.http.Smug-Cacheable = "No";
      set beresp.http.magicmarker = "1";
      set beresp.uncacheable = true;
    }

    # Stream large objects, <= 128 MiB
    if ((beresp.http.Content-Type ~ "(?i)(octet-stream)" || bereq.url ~ "^[^?]*\.(?i)(7z|avi|bz2|flac|flv|gz|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|ogm|opus|rar|tar|tgz|tbz|txz|wav|webm|xz|zip)(\?.*)?$") && std.integer(beresp.http.Content-Length,0) <= 134217728) {
      unset beresp.http.Set-Cookie;
      set beresp.do_stream = true;  # Check memory usage it'll grow in fetch_chunksize blocks (128k by default) if
      # the backend doesn't send a Content-Length header, so only enable it for big objects
      set beresp.do_gzip = false; # Don't try to compress it for storage
    }

    if (beresp.http.Content-Type ~ "(?i)(text|javascript|xml)" ||
      beresp.http.Content-Type ~ "(?i)application/(x-)?javascript" ||
      beresp.http.Content-Type ~ "(?i)application/(x-)?font-ttf" ||
      beresp.http.Content-Type ~ "(?i)application/(x-)?font-opentype" ||
      beresp.http.Content-Type ~ "(?i)application/font-woff" ||
      beresp.http.Content-Type ~ "(?i)application/vnd\.ms-fontobject" ||
      beresp.http.Content-Type ~ "(?i)image/svg\+xml") {
      set beresp.do_gzip = true;
    }

    if (beresp.status == 301 || beresp.status == 302) {
      set beresp.http.Location = regsub(beresp.http.Location, ":[0-9]+", "");
      set beresp.ttl = 1m;
      set beresp.grace = 5m;
      unset beresp.http.Server;
      return (deliver);
    }

    if (beresp.status == 403) {
      set beresp.ttl = 30s;
      set beresp.grace = 5m;
      return (deliver);
    } elsif (beresp.status == 404) {
      set beresp.ttl = 60s;
      set beresp.grace = 5m;
      return (deliver);
    }

    if (beresp.status >= 500 && beresp.status < 600 && bereq.retries < 5) {
      if (bereq.method != "POST") {
        set beresp.ttl = 10s;
        set beresp.grace = 5m;
        return(retry);
      }
    }

    if (beresp.http.Authorization ||
       beresp.http.Authenticate ||
       beresp.http.WWW-Authenticate ||
       beresp.http.X-Requested-With == "(?i)XMLHttpRequest") {
      /* Not cacheable by default */
      set beresp.http.Smug-Cacheable = "No";
      set beresp.http.magicmarker = "1";
      set beresp.uncacheable = true;
      return (deliver);
    }

    if (beresp.http.Set-Cookie) {
      set beresp.http.Smug-Cacheable = "No";
      set beresp.http.magicmarker = "1";
      set beresp.uncacheable = true;
      return (deliver);
    }

    if (beresp.http.Cache-Control ~ "private") {
      set beresp.http.Smug-Cacheable = "No";
      set beresp.http.magicmarker = "1";
      set beresp.uncacheable = true;
      return (deliver);
    }

    if (beresp.ttl <= 0s ||
      beresp.http.Set-Cookie ||
      beresp.http.Surrogate-control ~ "(?i)no-store" ||
      beresp.http.Edge-Control ~ "(?i)no-store" ||
      beresp.http.Pragma ~ "(?i)no-cache" ||
      (!beresp.http.Surrogate-Control && beresp.http.Cache-Control ~ "(?i)no-cache|no-store|private") ||
      #(!beresp.http.Cache-Control && !beresp.http.Expires) ||
      beresp.http.Vary == "*") {
        set beresp.ttl = 120s;
        set beresp.http.Smug-Cacheable = "No";
        set beresp.http.magicmarker = "1";
        set beresp.uncacheable = true;
        return (deliver);
    }

    set beresp.http.Expires = "" + (now + beresp.ttl);

    # Allow stale content, in case the backend goes down.
    # make Varnish keep all objects for 6 hours beyond their TTL
    set beresp.grace = 6h;

    return (deliver);
}

sub vcl_backend_error {
    return(abandon);
}

#Routine to identify and classify a device based on User-Agent
sub identify_device {
	unset req.http.X-UA-Device;
	set req.http.X-UA-Device = "pc";

	# Handle that a cookie may override the detection alltogether.
	if (req.http.Cookie ~ "(?i)X-UA-Device-force") {
		/* ;?? means zero or one ;, non-greedy to match the first. */
		set req.http.X-UA-Device = regsub(req.http.Cookie, "(?i).*X-UA-Device-force=([^;]+);??.*", "\1");
		/* Clean up our mess in the cookie header */
		set req.http.Cookie = regsuball(req.http.Cookie, "(^|; ) *X-UA-Device-force=[^;]+;? *", "\1");
		/* If the cookie header is now empty, or just whitespace, unset it. */
		if (req.http.Cookie ~ "^ *$") { unset req.http.Cookie; }
	} else {
        if (req.http.User-Agent ~ "\(compatible; Googlebot-Mobile/2.1; \+http://www.google.com/bot.html\)" ||
            (req.http.User-Agent ~ "(Android|iPhone)" && req.http.User-Agent ~ "\(compatible.?; Googlebot/2.1.?; \+http://www.google.com/bot.html") ||
            (req.http.User-Agent ~ "(iPhone|Windows Phone)" && req.http.User-Agent ~ "\(compatible; bingbot/2.0; \+http://www.bing.com/bingbot.htm")) {
            set req.http.X-UA-Device = "mobile-bot";
        } elsif (req.http.User-Agent ~ "(?i)(ads|google|bing|msn|yandex|baidu|ro|career|seznam|)bot" ||
            req.http.User-Agent ~ "(?i)(baidu|jike|symantec)spider" ||
            req.http.User-Agent ~ "(?i)scanner" ||
            req.http.User-Agent ~ "(?i)(web)crawler") {
            set req.http.X-UA-Device = "bot";
        } elsif (req.http.User-Agent ~ "(?i)ipad") {
            set req.http.X-UA-Device = "tablet-ipad";
        } elsif (req.http.User-Agent ~ "(?i)ip(hone|od)") {
            set req.http.X-UA-Device = "mobile-iphone";
        }
		/* how do we differ between an android phone and an android tablet?
		   http://stackoverflow.com/questions/5341637/how-do-detect-android-tablets-in-general-useragent */
		elsif (req.http.User-Agent ~ "(?i)android.*(mobile|mini)") { set req.http.X-UA-Device = "mobile-android"; }
		// android 3/honeycomb was just about tablet-only, and any phones will probably handle a bigger page layout.
		elsif (req.http.User-Agent ~ "(?i)android 3") { set req.http.X-UA-Device = "tablet-android"; }
		/* Opera Mobile */
		elsif (req.http.User-Agent ~ "Opera Mobi") { set req.http.X-UA-Device = "mobile-smartphone"; }
		// May very well give false positives towards android tablets. Suggestions welcome.
		elsif (req.http.User-Agent ~ "(?i)android") { set req.http.X-UA-Device = "tablet-android"; }
		elsif (req.http.User-Agent ~ "PlayBook; U; RIM Tablet") { set req.http.X-UA-Device = "tablet-rim"; }
		elsif (req.http.User-Agent ~ "hp-tablet.*TouchPad") { set req.http.X-UA-Device = "tablet-hp"; }
		elsif (req.http.User-Agent ~ "Kindle/3") { set req.http.X-UA-Device = "tablet-kindle"; }
		elsif (req.http.User-Agent ~ "Touch.+Tablet PC" || req.http.User-Agent ~ "Windows NT [0-9.]+; ARM;" ) {
		    set req.http.X-UA-Device = "tablet-microsoft";
		}
		elsif (req.http.User-Agent ~ "Mobile.+Firefox") { set req.http.X-UA-Device = "mobile-firefoxos"; }
		elsif (req.http.User-Agent ~ "^HTC" ||
		    req.http.User-Agent ~ "Fennec" ||
		    req.http.User-Agent ~ "IEMobile" ||
		    req.http.User-Agent ~ "BlackBerry" ||
		    req.http.User-Agent ~ "BB10.*Mobile" ||
		    req.http.User-Agent ~ "GT-.*Build/GINGERBREAD" ||
		    req.http.User-Agent ~ "SymbianOS.*AppleWebKit") {
			set req.http.X-UA-Device = "mobile-smartphone";
		}
		elsif (req.http.User-Agent ~ "(?i)symbian" ||
		    req.http.User-Agent ~ "(?i)^sonyericsson" ||
		    req.http.User-Agent ~ "(?i)^nokia" ||
		    req.http.User-Agent ~ "(?i)^samsung" ||
		    req.http.User-Agent ~ "(?i)^lg" ||
		    req.http.User-Agent ~ "(?i)bada" ||
		    req.http.User-Agent ~ "(?i)blazer" ||
		    req.http.User-Agent ~ "(?i)cellphone" ||
		    req.http.User-Agent ~ "(?i)iemobile" ||
		    req.http.User-Agent ~ "(?i)midp-2.0" ||
		    req.http.User-Agent ~ "(?i)u990" ||
		    req.http.User-Agent ~ "(?i)netfront" ||
		    req.http.User-Agent ~ "(?i)opera mini" ||
		    req.http.User-Agent ~ "(?i)palm" ||
		    req.http.User-Agent ~ "(?i)nintendo wii" ||
		    req.http.User-Agent ~ "(?i)playstation portable" ||
		    req.http.User-Agent ~ "(?i)portalmmm" ||
		    req.http.User-Agent ~ "(?i)proxinet" ||
		    req.http.User-Agent ~ "(?i)sonyericsson" ||
		    req.http.User-Agent ~ "(?i)symbian" ||
		    req.http.User-Agent ~ "(?i)windows\ ?ce" ||
		    req.http.User-Agent ~ "(?i)winwap" ||
		    req.http.User-Agent ~ "(?i)eudoraweb" ||
		    req.http.User-Agent ~ "(?i)htc" ||
		    req.http.User-Agent ~ "(?i)240x320" ||
		    req.http.User-Agent ~ "(?i)avantgo") {
			set req.http.X-UA-Device = "mobile-generic";
		}
	}
}
#######################################################################
# Housekeeping

sub vcl_fini {
    return (ok);
}




