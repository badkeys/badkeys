import sys
import argparse
import signal

from .checks import detectandcheck, allchecks, checkrsa
from .scanssh import scanssh
from .scantls import scantls

MAXINPUTSIZE = 10000

count = 0


def _sighandler(_signum, _handler):
    print(f"{count} keys processed")


def _printresults(key, where, verbose):
    if key['type'] == "unsupported":
        print(f"Warning: Unsupported key type, {where}", file=sys.stderr)
    elif verbose:
        print(f"{key['type']} key checked, {where}")
    for check, result in key['results'].items():
        sub = ""
        if 'subtest' in result:
            sub = f"/{result['subtest']}"
        print(f"{check}{sub} vulnerability found, {where}")
        if verbose and "debug" in result:
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
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose output")
    ap.add_argument("-t", "--tls", action="store_true",
                    help="Scan TLS (pass hostnames or IPs instead of files)")
    # default ports for https, smtps, imaps, pop3s, ldaps, ftps
    # and 8443 as a common non-default https port
    ap.add_argument("--tls-ports", default="443,465,636,990,993,995,8443",
                    help="TLS ports (comma-separated)")
    ap.add_argument("-s", "--ssh", action="store_true",
                    help="Scan SSH (pass hostnames or IPs instead of files)")
    ap.add_argument("--ssh-ports", default="22",
                    help="SSH ports (comma-separated)")
    args = ap.parse_args()

    if args.checks:
        userchecks = args.checks.split(",")
        for c in userchecks:
            if c not in allchecks:
                sys.exit(f"{c} is not a valid check")
    else:
        userchecks = allchecks.keys()

    if args.tls:
        ports = [int(p) for p in args.tls_ports.split(',')]
        for host in args.infiles:
            for port in ports:
                keys = scantls(host, port, userchecks)
                for k in keys:
                    _printresults(k, f"tls:{host}:{port}", args.verbose)

    if args.ssh:
        ports = [int(p) for p in args.ssh_ports.split(',')]
        for host in args.infiles:
            for port in ports:
                keys = scanssh(host, port)
                for k in keys:
                    _printresults(k, f"ssh:{host}:{port}", args.verbose)

    if args.ssh or args.tls:
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
                _printresults(r, f"modulus {n:02x}", args.verbose)
        else:
            fcontent = f.read(MAXINPUTSIZE)
            r = detectandcheck(fcontent, checks=userchecks)
            _printresults(r, fn, args.verbose)

        if fn != "-":
            f.close()
