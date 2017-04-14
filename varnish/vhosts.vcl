if (req.url == "/monit-check-url-varnish") {
  return (synth(200, "Varnish up"));
} else {
  # Use the default backend for all other requests
  set req.backend_hint = cluster.backend();
  #return (synth(403, "Hostname not found."));
}

