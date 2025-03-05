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

```
java -jar .\pqcli.jar cert -newkey Dilithium:3 -subj CN=Solanum
```
Generates a self-signed PQC X.509 Certificate using a Dilithium key pair.


```
java -jar .\pqcli.jar cert -newkey RSA,Dilithium:3
```
Generates a self-signed Hybrid (X.509 Section 9.8) Certificate with RSA as traditional and Dilithium as alternative signature algorithm.

```
java -jar .\pqcli.jar key -t sphincs+:192f
```
Generate a SPHINCS+ (SLH-DSA) keypair with SHA2-192f parameters.

```
java -jar .\pqcli.jar view certificate.pem
```
Examine an existing certificate in PEM format.

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
RSA | 1024-8192 | 2048
EC | All common named curves, e.g. `secp256r1` | `secp256r1`
DSA | 1024-4096 | 2048
Ed25519 | - | -
Ed448 | - | -
Dilithium | 2, 3, 5 | 3
SPHINCS+ | 128s, 128f, 192s, 192f, 256s, 256f (all SHA-2) | 192 (s)

Dilithium and SPHINCS+ have been standardised by NIST as FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA), respectively.
The authors did not yet verify that the BC v1.80 implementation of these algorithms is already fully standard-compliant.
