import sys
import argparse

from .checks import detectandcheck, allchecks, checkrsa

MAXINPUTSIZE = 10000


def runcli():
    ap = argparse.ArgumentParser()
    ap.add_argument("infiles", nargs='+',
                    help="Input file (certificate, csr or public key)")
    ap.add_argument("-c", "--checks",
                    help="Comma-separated list of checks (default: all)")
    ap.add_argument("-m", "--moduli", action="store_true",
                    help="Input file is list of RSA hex moduli")
    ap.add_argument("-d", "--debug", action="store_true",
                    help="Output debug messages	")
    args = ap.parse_args()

    if args.checks:
        userchecks = args.checks.split(",")
        for c in userchecks:
            if c not in allchecks:
                sys.exit(f"{c} is not a valid check")
    else:
        userchecks = allchecks.keys()

    for fn in args.infiles:
        if fn == "-":
            f = sys.stdin
        else:
            f = open(fn)
        if args.moduli:
            for line in f:
                n = int(line, 16)
                r = checkrsa(userchecks, n)
                for check, result in r.items():
                    print(f"{check} vulnerability found, modulus {n:02x}")
                    if args.debug and "debug" in result:
                        print(result["debug"])
        else:
            fcontent = f.read(MAXINPUTSIZE)
            r = detectandcheck(fcontent, userchecks)
            for check, result in r.items():
                print(f"{check} vulnerability found in {fn}")
                if args.debug and "debug" in result:
                    print(result["debug"])

        if fn != "-":
            f.close()
