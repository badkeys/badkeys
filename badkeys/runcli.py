import sys
import argparse
import signal
import ssl

from .checks import detectandcheck, allchecks, checkrsa, checkcrt

MAXINPUTSIZE = 10000

count = 0


def _sighandler(_signum, _handler):
    print(f"{count} keys processed")


def _printresults(key, where, debug):
    if key['type'] == "unsupported":
        print(f"Warning: Unsupported key type, {where}", file=sys.stderr)
    elif debug:
        print(f"{key['type']} key checked, {where}")
    for check, result in key['results'].items():
        sub = ""
        if 'subtest' in result:
            sub = f"/{result['subtest']}"
        print(f"{check}{sub} vulnerability found, {where}")
        if debug and "debug" in result:
            print(result["debug"])


def runcli():
    global count
    signal.signal(signal.SIGHUP, _sighandler)

    ap = argparse.ArgumentParser()
    ap.add_argument("infiles", nargs='+',
                    help="Input file (certificate, csr or public key)")
    ap.add_argument("-c", "--checks",
                    help="Comma-separated list of checks (default: all)")
    ap.add_argument("-m", "--moduli", action="store_true",
                    help="Input file is list of RSA hex moduli")
    ap.add_argument("-d", "--debug", action="store_true",
                    help="Output debug messages")
    ap.add_argument("-t", "--tls", action="store_true",
                    help="Scan TLS (pass hostnames or IPs instead of files)")
    ap.add_argument("-p", "--ports",
                    help="Ports to scan (TLS mode)")
    args = ap.parse_args()

    if args.checks:
        userchecks = args.checks.split(",")
        for c in userchecks:
            if c not in allchecks:
                sys.exit(f"{c} is not a valid check")
    else:
        userchecks = allchecks.keys()

    if args.tls:
        if args.ports:
            ports = []
            for p in args.ports.split(','):
                ports += int(p)
        else:
            # ports for https, smtps, imaps, pop3s, ldaps, ftps
            # and 8443 as most common non-default https port
            ports = [443, 465, 993, 995, 465, 636, 990, 8443]
        for host in args.infiles:
            for port in ports:
                try:
                    cert = ssl.get_server_certificate((host, port))
                except ConnectionRefusedError:
                    continue
                r = checkcrt(cert, checks=userchecks)
                _printresults(r, f"{host}:{port}", args.debug)

        sys.exit(1)

    for fn in args.infiles:
        if fn == "-":
            f = sys.stdin
        else:
            f = open(fn)
        if args.moduli:
            for line in f:
                count += 1
                if line.startswith("Modulus="):
                    line = line[8:]
                n = int(line, 16)
                r = {"type": "rsa"}
                r['results'] = checkrsa(n, checks=userchecks)
                _printresults(r, f"modulus {n:02x}", args.debug)
        else:
            fcontent = f.read(MAXINPUTSIZE)
            r = detectandcheck(fcontent, checks=userchecks)
            _printresults(r, fn, args.debug)

        if fn != "-":
            f.close()
