# pqcli
CLI wrapper for BouncyCastle with a particular focus on post-quantum hybrid certificates.

The goal is to create an easily usable interface to carry out cryptographic operations using the BouncyCastle library.

## Building

Uses Maven with JDK 23.

```shell
mvn clean package
```

This generates a complete .jar file in the `/target` dir.

## Usage

Example

```
java -jar .\pqcli.jar cert -newkey Dilithium:3 -sig Dilithium:3
```
Generates a Dilithium keypair with Dilithium signature.

### CLI structure (not yet implemented, not yet final)

This is an overview of the initial idea how the tool might be structured.

Command | Description
--- | ---
cert | Request a new X.509 public-key certificate
key | Generate cryptographic key(pairs)
csr | Generate a certificate signing request
(crl) | Generate a certificate revocation list
verify | Verify a certificate chain or signature (depending on parameters)
(sign) | Sign some data using a private key
view | Displays the contents of e.g. a certificate or key metadata in human-readable form

#### cert API

(not yet implemented, initial idea)
Option | Description
--- | ---
-ca | The certificate of the authority that is included in the issuer field of the certificate. If omitted, the certificate is self-signed.
-cakey | The private key of the CA, used to sign the certificate.
-days | The validity period of the certificate from today in days.
-key | The public key to certify. If omitted, a suitable keypair is generated.
-newkey | The algorithm(s) to use for the newly generated key
-sig | The signature algorithm(s) to use. Algorithms are separated by `,`, key size is speficied by `:`. (e.g. `rsa:3072,dilithium:3` for a PQC hybrid signature using 3072 byte RSA and Dilithium level 3 keys) 
-subj | The subject DN to include in the certificate (OpenSSL format, e.g. `/CN=Test/DC=testdc`)

#### key API

(initial idea)
Option | Description
--- | ---
-newkey / -new / -t | The algorithm(s) to use to generate a new keypair.

## TeX sources, example code and files for the PQC hybrid certificate paper
