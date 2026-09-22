class ServerHeaderMiddleware:
    """
    Mitigation: Server Leaks Version Information (CWE-200 / A02:2025 - Security
    Misconfiguration).

    The header cannot simply be deleted here: wsgiref writes its own
    "Server: <software_version>" in BaseHandler.send_preamble() whenever the
    application did not provide one. Setting a constant, version-free value
    takes that slot and suppresses the default. The same applies to gunicorn or
    uWSGI, so this mitigation survives a move to a production server.
    """

    SERVER_NAME = 'VaultChain'

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Server'] = self.SERVER_NAME
        return response
