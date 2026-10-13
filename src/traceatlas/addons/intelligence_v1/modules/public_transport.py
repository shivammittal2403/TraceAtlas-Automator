"""Public-address HTTP transport with DNS pinning and normal TLS verification."""
import http.client
import ipaddress
import socket
from urllib.request import HTTPHandler, HTTPSHandler, ProxyHandler, build_opener


def public_socket(host, port, timeout):
    # Resolve once per connection, validate EVERY answer, then connect to a numeric
    # sockaddr. Never pass the hostname to create_connection for a second lookup.
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers:
        raise OSError("No DNS addresses")
    for _, _, _, _, address in answers:
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global or ip.is_multicast:
            raise OSError("DNS resolved to a non-public address")
    last_error = None
    for family, kind, protocol, _, address in answers:
        sock = socket.socket(family, kind, protocol)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            sock.connect(address)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error or OSError("No reachable public address")


class PublicHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        if self._tunnel_host:
            raise OSError("Proxy tunnels are disabled")
        self.sock = public_socket(self.host, self.port, self.timeout)


class PublicHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        if self._tunnel_host:
            raise OSError("Proxy tunnels are disabled")
        raw = public_socket(self.host, self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class PublicHTTPHandler(HTTPHandler):
    def http_open(self, request):
        return self.do_open(PublicHTTPConnection, request)


class PublicHTTPSHandler(HTTPSHandler):
    def https_open(self, request):
        return self.do_open(PublicHTTPSConnection, request, context=self._context)


def public_opener(redirect_handler):
    # Include urllib's default HTTP error handler, but never ambient proxy settings.
    return build_opener(ProxyHandler({}), redirect_handler,
                        PublicHTTPHandler(), PublicHTTPSHandler())
