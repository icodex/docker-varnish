    if (req.http.user-agent ~ "MSIE [1-6]") {
      unset req.http.Accept-Encoding;
    }

    #if (req.http.user-agent ~ "MSIE") {
    #  set req.http.user-agent = "MSIE";
    #} else {
    #  set req.http.user-agent = "Mozilla";
    #}

    if (!client.ip ~ allow) {
      if (req.http.user-agent !~ "(Mozilla/4.0\ \(compatible;\ MSIE\ 6.0;\ Windows\ NT\ 5.1;\ SV1;\ .NET\ CLR\ 1.1.4322;\ .NET\ CLR\ 2.0.50727\)|Dalvik\/(.*)\ \(Linux;\ U;\ Android\ (.*);\ Android\ on\ sv8860\ Build\/(.*)\))") {
      #return (synth(720, "http://www.google.cn/ncr"));
      }
    }
