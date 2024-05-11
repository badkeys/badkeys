import contextlib
import io
import sys

from .checks import checksshpubkey, defaultchecks


def scanssh(host, port=22, checks=defaultchecks.keys()):
    try:
        import paramiko
    except ModuleNotFoundError:
        sys.stderr.write("ERROR: SSH scanning needs paramiko\n")
        return []

    allkeytypes = paramiko.Transport._preferred_keys

    keys = []
    for keytype in ["rsa", "dss", "ecdsa", "ed25519"]:
        try:
            xnot = [x for x in allkeytypes if keytype not in x]

            transp = paramiko.Transport(
                f"{host}:{port}", disabled_algorithms={"keys": xnot}
            )

            with contextlib.redirect_stderr(io.StringIO()):
                transp.connect()
            key = transp.get_remote_server_key()
            transp.close()

            pubsshkey = f"{key.get_name()} {key.get_base64()}"
            keys.append(checksshpubkey(pubsshkey, checks=checks))
        except paramiko.ssh_exception.IncompatiblePeer:
            # if we can't connect with this key type
            # we try the next
            continue
        except paramiko.ssh_exception.SSHException:
            # if we can't connect at all we don't try again
            break

    return keys
