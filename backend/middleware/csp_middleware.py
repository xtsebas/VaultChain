class ContentSecurityPolicyMiddleware:
    """
    Mitigation: CSP Header Not Set (CWE-693 / A02:2025 - Security Misconfiguration)
    This backend only exposes a JSON API; no active resource (scripts, styles,
    frames) should ever execute or load in the context of its responses.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Content-Security-Policy'] = "default-src 'none'"
        return response