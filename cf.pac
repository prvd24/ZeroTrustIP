function FindProxyForURL(url, host) {
  // No proxy for private (RFC 1918) IP addresses (intranet sites)
  if (
    isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
    isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
    isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")
  ) {
    return "DIRECT";
  }

  // No proxy for localhost
  if (isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
    return "DIRECT";
  }

  // Proxy all
  return "HTTPS 3ele0ss56t.proxy.cloudflare-gateway.com:443";
}
