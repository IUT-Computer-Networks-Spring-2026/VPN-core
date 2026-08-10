"""Tiny reverse-proxy helper for the panel frontends.

The Admin Panel and Client Portal are pure frontends: they do not own the
database. They serve HTML/JS and forward every /api/* call to the VPN Server's
HTTP API (the sole DB owner). This module performs that forwarding using only
the standard library (urllib) so no extra dependency is required.
"""

import urllib.request
import urllib.error
from flask import request, Response

# Headers we must not copy back verbatim from the upstream response.
_HOP_BY_HOP = {
    "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade", "content-encoding",
}


def proxy_request(api_base: str, path: str, timeout: float = 15.0) -> Response:
    """Forward the current Flask request to ``api_base + path`` and relay the reply.

    Forwards method, body, query string, the Authorization header and the
    ``token`` cookie; relays status, JSON body and any Set-Cookie header so the
    browser's auth cookie continues to work through the proxy.
    """
    url = api_base.rstrip("/") + path
    if request.query_string:
        url += "?" + request.query_string.decode("latin-1")

    body = request.get_data() or None
    headers = {}
    if request.headers.get("Content-Type"):
        headers["Content-Type"] = request.headers["Content-Type"]
    if request.headers.get("Authorization"):
        headers["Authorization"] = request.headers["Authorization"]
    token = request.cookies.get("token")
    if token:
        headers["Cookie"] = "token=" + token

    req = urllib.request.Request(url, data=body, method=request.method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as up:
            status = up.status
            payload = up.read()
            up_headers = up.headers
    except urllib.error.HTTPError as exc:
        status = exc.code
        payload = exc.read()
        up_headers = exc.headers
    except urllib.error.URLError:
        return Response('{"error":"VPN Server API is unreachable"}',
                        status=502, content_type="application/json")

    resp = Response(payload, status=status,
                    content_type=up_headers.get("Content-Type", "application/json"))
    set_cookie = up_headers.get("Set-Cookie")
    if set_cookie:
        resp.headers["Set-Cookie"] = set_cookie
    return resp
