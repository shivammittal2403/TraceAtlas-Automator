"""Fixed-origin HTTPS transport. No proxy, redirect or target-controlled host."""
from __future__ import annotations

import http.client
import ipaddress
import queue
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from .provider import ProviderError
from .contracts import SOURCE_HOSTS

MAX_BYTES = 5 * 1024 * 1024
PROVIDER_HOSTS = frozenset(SOURCE_HOSTS.values())


def _resolve(host, timeout):
    # OS DNS resolution has no portable timeout. Bound caller wait; an abandoned
    # daemon resolver cannot connect or send credentials after this call returns.
    result = queue.Queue(maxsize=1)
    def resolve():
        try:
            result.put(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
        except OSError:
            result.put(None)
    threading.Thread(target=resolve, daemon=True).start()
    try:
        addresses = result.get(timeout=timeout)
    except queue.Empty:
        raise ProviderError('provider_deadline_exceeded') from None
    if not addresses:
        raise ProviderError('provider_dns_failure', retryable=True)
    ips = list(dict.fromkeys(row[4][0] for row in addresses))
    if any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise ProviderError('provider_destination_rejected')
    return ips[0]


def request(url: str, headers: dict[str, str], timeout: float) -> tuple[int, bytes]:
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme == 'https' and parsed.hostname in PROVIDER_HOSTS
                 and parsed.port in {None, 443} and not parsed.username
                 and not parsed.password and not parsed.fragment
                 and not any(ord(c) < 33 for c in url))
    except ValueError:
        valid = False
    if not valid:
        raise ProviderError('provider_destination_rejected')
    deadline = time.monotonic() + max(0, min(float(timeout), 30))
    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise ProviderError('provider_deadline_exceeded')
        return seconds
    host = parsed.hostname
    ip = _resolve(host, remaining())
    context = ssl.create_default_context()
    raw = socket.create_connection((ip, 443), timeout=remaining())
    connection = None
    timer = None
    tls = None
    try:
        raw.settimeout(remaining())
        tls = context.wrap_socket(raw, server_hostname=host)
        connection = http.client.HTTPSConnection(host, timeout=remaining(), context=context)
        connection.sock = tls
        def expire():
            try:
                tls.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(remaining(), expire)
        timer.daemon = True
        timer.start()
        safe_headers = {k: v for k, v in headers.items()
                        if k.lower() not in {'host', 'accept-encoding', 'connection'}}
        safe_headers.update({'Accept-Encoding': 'identity', 'Connection': 'close'})
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        connection.request('GET', path, headers=safe_headers)
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ProviderError('provider_redirect_rejected')
        if response.status != 200:
            return response.status, b''
        if response.getheader('Content-Encoding', 'identity').lower() not in {'', 'identity'}:
            raise ProviderError('provider_encoding_rejected')
        media = response.getheader('Content-Type', '').split(';', 1)[0].strip().lower()
        if media != 'application/json' and not (media.startswith('application/') and media.endswith('+json')):
            raise ProviderError('provider_content_type_rejected')
        length = response.getheader('Content-Length')
        if length is not None and (not length.isdigit() or int(length) > MAX_BYTES):
            raise ProviderError('provider_response_too_large')
        body = response.read(MAX_BYTES + 1)
        remaining()
        if len(body) > MAX_BYTES:
            raise ProviderError('provider_response_too_large')
        return response.status, body
    except (OSError, http.client.HTTPException):
        raise ProviderError('provider_transport_failure', retryable=True) from None
    finally:
        if timer:
            timer.cancel()
        if connection:
            connection.close()
        if tls:
            tls.close()
        raw.close()
