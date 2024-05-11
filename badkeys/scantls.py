import ssl

from .checks import checkcrt, defaultchecks


def scantls(host, port=443, checks=defaultchecks.keys()):
    try:
        # this currently does not support multiple
        # certificates on one host
        cert = ssl.get_server_certificate((host, port))
    except (ConnectionRefusedError, ssl.SSLError, OSError):
        return []
    return [checkcrt(cert, checks=checks)]
