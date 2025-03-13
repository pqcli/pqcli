<div align="center">

![pqcli](.gh-assets/pqcli_banner.png)
**CLI wrapper for BouncyCastle with a particular focus on post-quantum hybrid certificates.**

</div>

> [!CAUTION]
> pqcli is currently intended for research purposes and in an early testing state. Do not use it in production.

The goal is to create an easily usable interface to carry out cryptographic operations using the BouncyCastle library.

## Building

Uses Maven with JDK 23.

```shell
mvn clean package
```

This generates a complete .jar file in the `/target` dir.

## Usage

Examples

Generate a self-signed PQC X.509 Certificate using a ML-DSA (Dilithium) key pair:
```
java -jar .\pqcli.jar cert -newkey Dilithium:3 -subj CN=Solanum
```

Generate a self-signed Hybrid (X.509 Section 9.8) Certificate with RSA as traditional and Dilithium as alternative signature algorithm:
```
java -jar .\pqcli.jar cert -newkey RSA,ML-DSA:3
```

Generate a self-signed Composite Certificate with RSA and Dilithium:
```
java -jar .\pqcli.jar cert -newkey ML-DSA_RSA
```

Generate a SPHINCS+ (SLH-DSA) keypair with SHA2-192f parameters:
```
java -jar .\pqcli.jar key -t slh-dsa:192f
```

Examine an existing certificate in PEM format:
```
java -jar .\pqcli.jar view certificate.pem
```

Non-practical example of a hybrid certificate that combines an RSA + ML-DSA composite key with another composite key of ECC, SLH-DSA, Ed448 and RSA again for good measure. Yep, we know...
```
java -jar .\target\pqcli-0.1.0.jar cert -newkey rsa:4096_mldsa,ec_slhdsa:256f_ed448_rsa:3072
```

### CLI structure (not yet implemented, not yet final)

This is an overview of the initial idea how the tool might be structured.

Command | Description | Impl.
--- | --- | ---
cert | Request a new X.509 public-key certificate | ✔️
key | Generate cryptographic key(pairs) | ✔️
csr | Generate a certificate signing request
(crl) | Generate a certificate revocation list
verify | Verify a certificate chain or signature (depending on parameters)
(sign) | Sign some data using a private key
view | Displays the contents of e.g. a certificate or key metadata in human-readable form | ✔️

#### cert API

(not yet implemented, initial idea)
Option | Description | Impl.
--- | --- | ---
-ca | The certificate of the authority that is included in the issuer field of the certificate. If omitted, the certificate is self-signed. |
-cakey | The private key of the CA, used to sign the certificate. |
-days | The validity period of the certificate from today in days. Defaults to one year. | ✔️
-key | The public key to certify. If omitted, a suitable keypair is generated. |
-newkey | The algorithm(s) to use for the newly generated key. Algorithms are separated by `,`, key size is speficied by `:`. (e.g. `rsa:3072,dilithium:3` for a PQC hybrid signature using 3072 byte RSA and Dilithium level 3 keys) | ✔️
-sig | The algorithm(s) to use for the signing key(s). |
-subj | The subject DN to include in the certificate (supports both OpenSSL and X500 format, e.g. `/CN=Test/DC=testdc` or `CN=Test, DC=testdc`) | ✔️

#### key API

(initial idea)
Option | Description | Impl.
--- | --- | ---
-newkey / -new / -t | The algorithm(s) to use to generate a new keypair, e.g. `rsa:2048`. | ✔️

#### Supported signature key algorithms

Algorithm | Key sizes | Default parameter
--- | --- | ---
ML-DSA (Dilithium) | 44, 65, 87 (or 2, 3, 5) | 3
dilithium-bcpqc | 2, 3, 5 | 3
SLH-DSA (SPHINCS+) | 128s, 128f, 192s, 192f, 256s, 256f (all SHA-2) | 192 (s)
RSA | 1024-8192 (append `-pss` for using RSASSA-PSS, e.g. `rsa:3072-pss`) | 2048
EC | All common named curves, e.g. `secp256r1` | `secp256r1`
DSA | 1024-4096 | 2048
Ed25519 | - | -
Ed448 | - | -

Note: `dilithium-bcpqc` is the Dilithium implementation from the BouncyCastle Post-Quantum Security Provider, which BC 1.79+ no longer supports for certificate signing.
It is provided for keypair generation and A/B testing only.

## Acknowledgements

PQCLI is partially funded as a part of the [Trustpoint](https://industrial-security.io) project sponsored by the German Federal Ministry of Education and Research.