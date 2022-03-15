import ssl

from .checks import checkcrt, allchecks


def scantls(host, port=443, checks=allchecks.keys()):
    try:
        # this currently does not support multiple
        # certificates on one host
        cert = ssl.get_server_certificate((host, port))
    except (ConnectionRefusedError, ssl.SSLError):
        return []
    return [checkcrt(cert, checks=checks)]
