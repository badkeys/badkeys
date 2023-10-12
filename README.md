# badkeys

Tool and library to check cryptographic public keys for known vulnerabilities

# what?

badkeys checks public keys in a variety of formats for known vulnerabilities.
A web version can be found at [badkeys.info](https://badkeys.info/).

# install

badkeys can be installed [via pip](https://pypi.org/project/badkeys/):
```
pip3 install badkeys
```

Alternatively you can call _./badkeys-cli_ directly from the git repository.

# usage

Before using badkeys you need to download the blocklist data:
```
badkeys --update-bl
```

After that you can call _badkeys_ and pass files with cryptographic
public keys as the parameter:
```
badkeys test.crt my.key
```

It will automatically try to detect the file format. Supported are public and
private keys in PEM format (both PKCS #1 and PKCS #8), X.509 certificates,
certificate signing requests (CSRs) and SSH public keys.
You can find some test keys in the _tests/data_ directory.

By default badkeys will only output information about vulnerable keys, meaning
there will be no output if no vulnerabilities are found. The _-a_ parameter
creates output for all keys.

# scanning

badkeys can directly scan SSH and TLS hosts and automatically check their public
keys. This can be enabled with the parameters _-s_ (for SSH) and _-t_ (for TLS).
By default SSH will be scanned on port 22 and TLS will be scanned on several
ports for common protocols (https/443, smtps/465, ldaps/636, ftps/990,
imaps/993, pop3s/995 and 8443, which is commonly used as a non-standard https port).

Alternative ports can be configured with _--tls-ports_ and _--ssh-ports_.

TLS and SSH scanning can be combined:
```
badkeys -ts example.org
```

# Python module and API

badkeys can also be used as a Python module. However currently the software is
in alpha state and the API may change regularly.

# about

badkeys was written by [Hanno Böck](https://hboeck.de).

This work was funded in part by Industriens Fond through the CIDI project
(Cybersecure IOT in Danish Industry) and in part by the
[Center for Information Security and Trust (CISAT)](https://cisat.dk/)
at the IT University of Copenhagen, Denmark.
