badkeys blocklist format and _BKHASH_
=====================================

The **badkeys** `blocklist` module checks inputs against a list of known-compromised
private keys. We also call them _Public Private Keys_. Such _Public Private Keys_
include ones resulting from key generation vulnerabilities with weak random number
generators that allow iterating over all or most generated keys. The most prominent
example is the Debian OpenSSL Bug (CVE-2008-0166). Furthermore, this includes example
keys from standardization documents, test suites, hardcoded keys in firmware files, and
many more.


**badkeys** uses a sorted blocklist of hashes to identify _Public Private Keys_. Due to
its size and frequent updates, the blocklist is not part of the badkeys software. It is
stored in the `~/.cache/badkeys/` directory and can be fetched and updated with the
`--update-bl` or `--update-bl-and-urls` parameter. (The latter will also update the
optional URL lookup file.)

The blocklist is created by the [`blocklistmaker`
](https://github.com/badkeys/blocklistmaker/) script. The used sources of compromised
keys are documented there.

_BKHASH_
========

A common practice to identify public and private keys is to hash them encoded in the
`subjectPublicKeyInfo` format (see [RFC 5280](
https://datatracker.ietf.org/doc/html/rfc5280)). However, **badkeys** does not use this
approach.

For each key type, **badkeys** uses a specific numeric value of the public key, encodes
it to bytes without leading zeros, and hashes it with SHA256. This hash is truncated to
either 120 or 64 bits (the motivation for this is explained below). We will call this
_BKHASH_, or, if we refer to a truncated version, _BKHASH120_ or _BKHASH64_.

Hashing a single numeric value has the advantage of avoiding key encoding ambiguities.
While those ambiguities are often not conformant with the specification, they still
commonly appear in real-world keys.

RSA
---

An RSA public key consists of two values, the modulus `N` and the public exponent `e`.
**badkeys** uses a hash of `N` to identify compromised RSA keys. (In practice, most RSA
keys use `e=65537`, but other values are possible. It is recommended to use this default
value, as it avoids multiple attacks both with very small and very large `e` values.)

Identifying a key by its `N` value means that there can be multiple keys identified by
the same hash. However, this is a desirable property and improves detection rates.

It is possible to have multiple keys with the same `N` value and different `e` values.
However, in this case, either all keys are secure or all keys are compromised. Imagine
two RSA pubic keys `k₁=(N₁,e₁)` and `k₂=(N₁,e₂)`, and the private key value `d₁` of `k₁`
is known. In this case, one can trivially factor `N₁` with the help of `d₁` and get `p`
and `q`. (An algorithm for this is given in the [Handbook of Applied Cryptography](
https://galois.azc.uam.mx/mate/propaganda/Menezes.pdf), chapter 8.2.2(i).) With `p`, `q`
, and `e₂`, it is possible to generate the full private key belonging to `k₂` the same
way one would do during RSA key generation. (To reconstruct RSA private keys from
partial information, e.g., only knowing `N`, `e`, and `d`, [Python Cryptography contains
various functions](
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#handling-partial-rsa-private-keys).
Alternatively, [`rsatool`](https://github.com/ius/rsatool) is a convenient command-line
tool for RSA private key recovery.)

The Debian OpenSSL bug is a good example of why it is valuable to identify keys by their
hashed `N` value. The vulnerable OpenSSL package generated keys based on a limited
number of inputs, like the process id or the architecture. However, the number of
variations is quite large. (**badkeys** detects over 2 million such keys.)

By default, the affected OpenSSL-generated keys have the public exponent value
`e=65537`. But the old version of OpenSSL's `genrsa` command-line tool allowed setting
the value to `e=3` via the `-3` parameter. Detecting these additional keys would
significantly increase the size of the blocklist when using both the `N` and `e` value.
By identifying keys by their `N` values, vulnerable keys with `e=3` are automatically
covered.

ECDSA
-----

Public keys for ECDSA are the coordinates of a point on an elliptic curve. This point
can be stored as `x` and `y` coordinates or by using point compression. The latter only
stores `x` and limited information about `y`, which allows it to be calculated.

**badkeys** uses the hashed `x` value to identify ECDSA keys. This avoids having to deal
with different point encoding formats.

DSA / DH
--------

DSA public keys and Diffie-Hellman keys consist of a value `y` and several parameter
values. **badkeys** uses the `y` value to identify keys.

Note that DSA keys are largely considered obsolete, and static Diffie-Hellman keys have
never been widely used.

Ed25519 / X25519 / Ed448 / X448
-------------------------------

These elliptic curve keys come with their own public key point compression format, which
differs from the traditional way ECDSA keys are encoded.

**badkeys** directly converts the public key bytes into an integer. This may appear
unusual compared to the other key formats where a numeric key value is used. (This was
initially based on a misunderstanding of the key format.)

blocklist file format
---------------------

The blocklist consists of three files: `badkeysdata.json`, `blocklist.dat`, and
(optional) `lookup.txt`.

The `badkeysdata.json` file (see [template](
https://github.com/badkeys/blocklistmaker/blob/main/template.badkeysdata.json)) should
be mostly self-explanatory. It contains a format version (`bkformat`, currently `0`),
the URLs (`blocklist_url`, `lookup_url`) and SHA256 hashes (`blocklist_sha256`,
`lookup_sha256`) of the other two files, the date and time of the last update (`date`,
ISO 8601 format), and a list of `blocklists`. Each entry contains a numeric `id`, a
`name, a type` (this is usually `github`, with the exception of the pseudo-type `new`
for yet unpublished keys), the repository URL path (`repo`), and the `path` within the
repository (including the branch name).

While we do not need cryptographic security for the hash, it needs to be long enough to
avoid accidental collisions. Yet, the blocklist is large enough that we want to avoid
needlessly increasing its size, which is why it does not use the full SHA256 hash. We
use the 120-bit truncated SHA256 value _BKHASH120_, which is long enough to plausibly
avoid accidental collisions.

The `blocklist.dat` is a binary file that contains sorted 128-bit blocks, which allows
using an efficient binary search. Each block consists of a _BKHASH120_ value and a
one-byte blocklist id. This allows **badkeys** to quickly get a rough classification of
the type of vulnerable key. (E.g., it allows to identify a key vulnerability as
`blocklist/debianssl` and not just `blocklist`.)

The `lookup.txt` file is needed to identify specific keys. With the `-u`/`--url`
parameter, **badkeys** will construct the URL of the key within the publicly available
compromised key collections.

The `lookup.txt` file is a sorted ASCII text file where each line starts with a
lowercase hex-encoded _BKHASH64_ value. We can use a shorter value, as the likelihood of
a collision within our known compromised keys is much smaller than the likelihood of a
hash collision in large public key collections. A colon (`;`) separates the _BKHASH64_
value from the key path. To get the full URL, this information needs to be combined with
the information in the `badkeysdata.json` file.

File size considerations
------------------------

The `blocklist.dat` is currently around 60 MB (50 MB compressed), and the `lookup.txt`
file is around 200 MB (55 MB compressed). The files are stored xz-compressed on the
server and unpacked after download.

While these are still very manageable file sizes, they are large enough to consider
options to reduce them.

It would be possible to use a more efficient hash representation in the `lookup.txt`
file — like base64 or base85. A hexadecimal representation was initially chosen to avoid
sorting ambiguities.

Using a Bloom filter could shrink the file size, but it would introduce an error rate.
Limiting that error rate to acceptable values would undo most of the benefit.

Given that the file sizes are still manageable, the blocklist is only growing slowly,
and changing the file format comes with considerable transition costs, no changes are
currently planned for the blocklist format.
