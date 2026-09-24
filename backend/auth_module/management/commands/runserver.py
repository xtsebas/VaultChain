"""
Custom runserver command: overrides Django's development server to avoid
leaking Python/WSGIServer version information in the "Server" HTTP header
(CWE-200 / OWASP A02:2025 - Security Misconfiguration).

Responses produced by the Django stack already get their "Server" header from
middleware.server_header_middleware.ServerHeaderMiddleware. The patches below
cover the two paths that never reach that middleware:

  * ServerHandler.server_software -> written by wsgiref's send_preamble() when
    the WSGI application does not set a Server header itself.
  * WSGIRequestHandler.server_version / sys_version -> used by
    BaseHTTPRequestHandler.version_string(), which the dev server calls for
    responses it generates on its own (malformed requests, 400/501 errors).

This module is imported before the server starts, and again in the autoreloader
child process, so the patch is always in place.
"""
from django.contrib.staticfiles.management.commands.runserver import (
    Command as StaticFilesRunserverCommand,
)
from django.core.servers.basehttp import ServerHandler, WSGIRequestHandler

from middleware.server_header_middleware import ServerHeaderMiddleware

ServerHandler.server_software = ServerHeaderMiddleware.SERVER_NAME
WSGIRequestHandler.server_version = ServerHeaderMiddleware.SERVER_NAME
WSGIRequestHandler.sys_version = ''
# version_string() joins server_version and sys_version with a space; override it
# so the emptied sys_version does not leave a trailing space in the header.
WSGIRequestHandler.version_string = lambda self: ServerHeaderMiddleware.SERVER_NAME


class Command(StaticFilesRunserverCommand):
    pass
