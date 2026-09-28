// llm-firewall PAC template.
//
// `llmfw-setup install` fills in {{PROXY_PORT}} (from proxy.listen_port) and writes
// the result to ~/Library/Application Support/llm-firewall/claude.pac. The launcher
// passes it ONLY to Claude.app via --proxy-pac-url. System proxy settings and
// browsers are never changed.
//
// Behavior:
//   * Only https:// and wss:// requests to claude.ai, *.claude.ai, anthropic.com and
//     *.anthropic.com go to the proxy. Everything else returns "DIRECT".
//   * "; DIRECT" is the fail-open fallback. If nothing is listening on the port,
//     Chromium connects directly and Claude keeps working. Only logging is lost.
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
