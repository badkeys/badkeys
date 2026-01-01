import argparse
import json
import re
import signal
import sys

from . import __version__
from .allkeys import loadextrabl, urllookup
from .checks import (allchecks, checkcrt, checkpubkey, checkrsa, checksshpubkey, defaultchecks,
                     detectandcheck)
from .dkim import parsedkim
from .dnssec import checkdnskey
from .jwk import checkjwk
from .scanssh import scanssh
from .scantls import scantls
from .update import update_bl
from .utils import _errexit, _getret, _setret, _warnmsg

MAXINPUTSIZE = 2048000

count = 0

PRECRT = "-----BEGIN CERTIFICATE-----\n"
POSTCRT = "\n-----END CERTIFICATE-----\n"


def _sighandler(_signum, _handler):
    print(f"{count} keys processed", file=sys.stderr)


def _printresults(key, where, args):
    if args.json:
        jout = key
        for val in ["n", "e", "x"]:
            if val in jout:
                jout[val] = f"{jout[val]:x}"
        for result in jout["results"]:
            if "p" in jout["results"][result]:
                jout["results"][result]["p"] = f'{jout["results"][result]["p"]:x}'
                jout["results"][result]["q"] = f'{jout["results"][result]["q"]:x}'
        print(json.dumps(jout))
        return
    kn = key["type"]
    if "bits" in key:
        kn += f"[{key['bits']}]"
    if "curve" in key:
        kn += f"[{key['curve']}]"
    if key["type"] == "unsupported":
        _warnmsg(f"Unsupported key type, {where}")
    elif key["type"] == "unparseable":
        _warnmsg(f"Unparseable input, {where}")
    elif key["type"] == "notfound":
        _warnmsg(f"No key found, {where}")
    elif args.verbose or args.all:
        if key["results"] == {}:
            print(f"{kn} key ok, {where}")
    for check, result in key["results"].items():
        sub = ""
        if "subtest" in result:
            sub = f"/{result['subtest']}"
        print(f"{check}{sub} vulnerability, {kn}, {where}")
        _setret(4)
        if args.url and "lookup" in result:
            url, _ = urllookup(result["blid"], result["lookup"])
            if url:
                print(url)
            else:
                _warnmsg("URL lookup failed, not found")
        if args.verbose and "debug" in result:
            print(result["debug"])
        if args.verbose and "p" in result:
            print(f"RSA p {result['p']:02x}")
        if args.verbose and "q" in result:
            print(f"RSA q {result['q']:02x}")


def runcli():
    global count
    try:
        signal.signal(signal.SIGHUP, _sighandler)
    except AttributeError:  # for OSes without SIGHUP (e.g. Windows)
        pass

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "infiles", nargs="*", help="Input file (certificate, csr or public key)"
    )
    ap.add_argument(
        "-c", "--checks", help="Comma-separated list of checks (default: all)"
    )
    ap.add_argument("--list", action="store_true", help="Show list of possible checks")
    ap.add_argument(
        "-m",
        "--moduli",
        action="store_true",
        help="Input file is list of RSA hex moduli",
    )
    ap.add_argument(
        "--crt-lines", action="store_true", help="Input file is list of base64 certs"
    )
    ap.add_argument(
        "--ssh-lines", action="store_true", help="Input file is list of ssh public keys"
    )
    ap.add_argument("--dkim", action="store_true", help="Scan DKIM records (in files)")
    ap.add_argument(
        "--dkim-dns",
        action="store_true",
        help="Scan DKIM DNS record (hostnames instead of files)",
    )
    ap.add_argument("--dnssec", action="store_true", help="Scan DNSKEY/DNSSEC records (in files)")
    ap.add_argument("--jwk", action="store_true", help="Scan JSON Web Keys / Key Sets")
    ap.add_argument("-a", "--all", action="store_true", help="Show all keys")
    ap.add_argument(
        "-w",
        "--warnings",
        action="store_true",
        help="Enable extra warnings (keysize etc.)",
    )
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    ap.add_argument("-j", "--json", action="store_true", help="JSON output")
    ap.add_argument(
        "-q", "--quiet", action="store_true", help="Quiet output (for update commands)"
    )
    ap.add_argument(
        "-u", "--url", action="store_true", help="Show private key URL if possible"
    )
    ap.add_argument("--update-bl", action="store_true", help="Update blocklist")
    ap.add_argument(
        "--update-bl-and-urls",
        action="store_true",
        help="Update blocklist and optional URL lookup list",
    )
    ap.add_argument("--extrabl", help="comma-separated list of extra blocklist files")
    ap.add_argument(
        "-t",
        "--tls",
        action="store_true",
        help="Scan TLS (pass hostnames or IPs instead of files)",
    )
    # default ports for https, smtps, imaps, pop3s, ldaps, ftps
    # and 8443 as a common non-default https port
    ap.add_argument(
        "--tls-ports",
        default="443,465,636,990,993,995,8443",
        help="TLS ports (comma-separated)",
    )
    ap.add_argument(
        "-s",
        "--ssh",
        action="store_true",
        help="Scan SSH (pass hostnames or IPs instead of files)",
    )
    ap.add_argument("--ssh-ports", default="22", help="SSH ports (comma-separated)")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args()

    if (
        (args.moduli and args.crt_lines)
        or (args.moduli and args.ssh_lines)
        or (args.ssh_lines and args.crt_lines)
    ):
        _errexit("Multiple input format parameters cannot be combined.")

    if (args.moduli or args.crt_lines or args.ssh_lines) and (
        args.tls or args.ssh or args.dkim_dns
    ):
        _errexit("Scan modes and input file modes cannot be combined.")

    if args.update_bl_and_urls:
        update_bl(lookup=True, quiet=args.quiet)
        sys.exit()
    if args.update_bl:
        update_bl(quiet=args.quiet)
        sys.exit()

    if args.list:
        for k, v in allchecks.items():
            print(f"{k}/{v['type']} keys: {v['desc']}")
        sys.exit()

    if not args.infiles:
        ap.print_help()
        sys.exit(1)

    if args.extrabl:
        extrabl = args.extrabl.split(",")
        for bl in extrabl:
            loadextrabl(bl)

    if args.checks:
        userchecks = args.checks.split(",")
        for c in userchecks:
            if c not in allchecks:
                _errexit(f"{c} is not a valid check")
    elif args.warnings:
        userchecks = allchecks.keys()
    else:
        userchecks = defaultchecks.keys()

    if args.tls:
        ports = [int(p) for p in args.tls_ports.split(",")]
        for host in args.infiles:
            for port in ports:
                keys = scantls(host, port, userchecks)
                for k in keys:
                    _printresults(k, f"tls:{host}:{port}", args)

    if args.ssh:
        ports = [int(p) for p in args.ssh_ports.split(",")]
        for host in args.infiles:
            for port in ports:
                keys = scanssh(host, port)
                for k in keys:
                    _printresults(k, f"ssh:{host}:{port}", args)

    if args.dkim_dns:
        try:
            import dns.resolver
        except ModuleNotFoundError:
            _errexit("DKIM DNS record scanning needs dnspython")
        for host in args.infiles:
            try:
                records = dns.resolver.resolve(host, "TXT").response
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                _warnmsg(f"No TXT record found, {host}")
                continue
            found = False
            for record in records.answer[-1]:
                dk = b"".join(record.strings).decode()
                key = parsedkim(dk)
                if key:
                    r = checkpubkey(key, checks=userchecks)
                    _printresults(r, host, args)
                    found = True
            if not found:
                _warnmsg(f"No DKIM/DomainKeys key in TXT record, {host}")

    if args.jwk:
        for fn in args.infiles:
            with open(fn) as f:
                try:
                    j = json.load(f)
                except (json.decoder.JSONDecodeError, UnicodeDecodeError):
                    _warnmsg(f"No valid JSON, {fn}")
                    continue
            if isinstance(j, dict) and "kty" in j:
                r = checkjwk(j, checks=userchecks)
                _printresults(r, fn, args)
            elif isinstance(j, dict) and "keys" in j:
                for k in j["keys"]:
                    r = checkjwk(k, checks=userchecks)
                    _printresults(r, fn, args)
            else:
                _warnmsg(f"No JWK/JWKS, {fn}")

    if args.ssh or args.tls or args.dkim_dns or args.jwk:
        sys.exit(_getret())

    if args.dnssec:
        dnskeyre = re.compile(r"[0-9]{1,3}\s+[0-9]{1,3}\s+[0-9]{1,3}\s+[A-Za-z0-9/+= ]+")

    for fn in args.infiles:
        if fn == "-":
            f = sys.stdin
        else:
            f = open(fn, errors="replace")
        if args.moduli:
            for line in f:
                count += 1
                if line.startswith("Modulus="):
                    n = int(line[8:], 16)
                else:
                    n = int(line, 16)
                r = {"type": "rsa", "bits": n.bit_length()}
                r["results"] = checkrsa(n, checks=userchecks)
                _printresults(r, f"modulus {n:02x}", args)
        elif args.crt_lines:
            lno = 0
            for line in f:
                desc = f"{fn}[{lno}]"
                ll = re.split("[,; ]", line.rstrip(), maxsplit=1)
                if len(ll) == 2:
                    desc += f" {ll[1]}"
                crt = PRECRT + ll[0] + POSTCRT
                r = checkcrt(crt, checks=userchecks)
                _printresults(r, desc, args)
                lno += 1
                count += 1
        elif args.ssh_lines:
            lno = 0
            for line in f:
                desc = f"{fn}[{lno}]"
                ll = line.rstrip().split(" ", 2)
                if len(ll) == 3:
                    desc += f" {ll[2]}"
                r = checksshpubkey(line, checks=userchecks)
                _printresults(r, desc, args)
                lno += 1
                count += 1
        elif args.dkim:
            lno = 0
            for line in f:
                desc = f"{fn}[{lno}]"
                key = parsedkim(line)
                if key:
                    r = checkpubkey(key, checks=userchecks)
                    _printresults(r, desc, args)
                    count += 1
                lno += 1
        elif args.dnssec:
            fcontent = f.read(MAXINPUTSIZE)

            keyrecs = dnskeyre.findall(fcontent)
            if not keyrecs:
                _warnmsg(f"No DNSSEC key found, {fn}")
            for rec in keyrecs:
                r = checkdnskey(rec, checks=userchecks)
                _printresults(r, fn, args)
                count += 1
        else:
            fcontent = f.read(MAXINPUTSIZE)
            r = detectandcheck(fcontent, checks=userchecks)
            _printresults(r, fn, args)

        if fn != "-":
            f.close()

    sys.exit(_getret())
