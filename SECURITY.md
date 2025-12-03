# badkeys Security

Being a security tool, it should obviously be the goal that `badkeys` itself is as
secure as possible.


## Reporting a Vulnerability

If you have found a severe security bug that you want to report confidentially, please
contact [Hanno Böck](https://hboeck.de/en/contact.html) directly.

Low-impact security issues can be directly reported to the [badkeys issue tracker](
https://github.com/badkeys/badkeys/issues).

## Security Considerations and Threat Model

### Malicious or malformed inputs

Given that `badkeys` is a software that reads and processes cryptographic keys in
various formats, the most likely attack surface for any security issues is the
processing of untrusted inputs.

`badkeys` should be able to handle malformed and malicious input files. The following
types of issues would be severe security vulnerabilities:

* A malicious input can trigger the execution of malicious code.

* A malicious input can trigger any kind of network request.

* A malicious input can exfiltrate information about the system via the program's
  output.

Malformed input files that cannot be scanned should cause a warning, but no abnormal
application behavior. The following types of issues would be treated as denial of
service issues that should be fixed, but their security impact is less severe:

* A malformed input causes an unexpected termination of the badkeys application, e.g.,
  by causing an OOM condition, a crash, or an unexpected exception. (Note, however, the
  caveat below regarding dependencies.)

* A malformed input causes an endless loop, an excessively long processing time, or
  excessive resource consumption.

### Blocklist updates

The `blocklist` functionality requires downloading a list of hashes of known-compromised
keys and optionally a list of URLs via the `--update-bl` or `--update-bl-and-urls`
parameters. This fetches the latest blocklist updates via HTTPS from
`update.badkeys.info`.

The connection is TLS-protected. A network attacker would naturally be able to prevent
an update from succeeding. However, any issue where a network attacker can tamper with
the connection in a way that causes `badkeys` to download and use a manipulated
blocklist update would be a severe security flaw.

Another potential scenario would be a compromised server or web certificate. If an
attacker is able to serve TLS-protected content to `badkeys`, it is expected that he
could serve a malformed blocklist that will not function correctly and may terminate
unexpectedly. However, a malformed blocklist should not cause malicious code execution,
network requests, or data exfiltration. Any such issue would also be treated as a
security vulnerability.

### Infrastructure

The security of a software relies to a certain degree on its infrastructure. Reports
about security issues of the [badkeys.info](https://badkeys.info/) web page ([source
code](https://github.com/badkeys/bkweb)), the server where it is hosted, the [code
repositories](https://github.com/badkeys/), or the [pypi packages](
https://pypi.org/project/badkeys/) are also appreciated and will be addressed
accordingly.

### Inconclusive list

Lists of potential security issues are always incomplete, as the most severe and
interesting security issues are often the ones one has not thought about.

## Security issues and bugs in dependencies

`badkeys` relies on functionality provided by dependencies. Naturally, this means that
security issues and bugs in dependencies can cause problems in `badkeys`.

Obviously, bugs and security issues in dependencies should be fixed. However, `badkeys`
will usually not implement workarounds to address bugs in other software.

An example: key parsing by `badkeys` relies on the Python [`cryptography`
](https://cryptography.io/) package. During the development of `badkeys` and its
supporting tools, bugs in `cryptography`'s key parsers were uncovered that [could cause
unexpected exceptions](https://github.com/pyca/cryptography/issues/13050). Such bugs can
cause an abnormal program termination of `badkeys` when using an outdated version of
`cryptography`. That is, however, not treated as a bug in `badkeys`.

It is recommended to run `badkeys` with the latest versions of its dependencies.
Currently, all known parser issues in `cryptography` have been addressed in version
46.0.3.

Security issues or parser bugs in dependencies should be reported to those projects
directly. However, if you discover any bugs in dependencies during the use of `badkeys`,
I would appreciate a note.
