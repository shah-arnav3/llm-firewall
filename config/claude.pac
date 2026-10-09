// llm-firewall PAC template.
//
// llmfw-proxy replaces the port token below with the port it is listening on and
// serves the result at http://127.0.0.1:<port>/proxy.pac. Claude Desktop fetches it at
// launch because its egressProxyPacUrl setting points there (the profile from
// `llmfw-setup profile`). The app evaluates it per request, the Cowork VM gets its own
// copy, and the Claude Code engine is given the one proxy it returns for the inference
// endpoint. System proxy settings and browsers are never changed.
//
// Behavior:
//   * Only https:// and wss:// requests to claude.ai, *.claude.ai, anthropic.com and
//     *.anthropic.com go to the proxy. Everything else returns "DIRECT".
//   * "; DIRECT" is the fail-open fallback. If nothing is listening on the port,
//     Claude's app connects directly and keeps working. Only logging is lost. (If the
//     proxy is down when Claude starts, the PAC cannot be fetched and Claude connects
//     directly for that whole session.)
//   * Plain http:// is never proxied, so the proxy only has to handle CONNECT.
//
// Keep this function trivial. Chromium evaluates it for every request.

function FindProxyForURL(url, host) {
  var h = host.toLowerCase();
  var u = url.toLowerCase();

  if (u.substring(0, 6) !== "https:" && u.substring(0, 4) !== "wss:") {
    return "DIRECT";
  }

  if (h === "claude.ai" || dnsDomainIs(h, ".claude.ai") ||
      h === "anthropic.com" || dnsDomainIs(h, ".anthropic.com")) {
    return "PROXY 127.0.0.1:{{PROXY_PORT}}; DIRECT";
  }

  return "DIRECT";
}
