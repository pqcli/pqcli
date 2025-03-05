package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.Callable;
import java.util.Date;
import java.util.regex.*;

@Command(name="cert", description="Generates an X.509 v3 certificate with a public/private key pair")
public class CertificateGenerator implements Callable<Integer> {

    @Option(names = { "-sig", "-s" }, description = "Signature algorithm (e.g. SHA256withRSA or SHA3-512withDilithium)")
    private String signatureAlgorithm;

    @Option(names = { "-newkey", "-nk" }, description = "Key algorithm (e.g. RSA:4096, EC, DSA or Dilithium:3)", required = true)
    private String keyAlgorithm;

    @Option(names = { "-days", "-d" }, description = "Certificate validity in days", required = false, defaultValue = "365")
    private String validityDays;

    @Option(names = { "-subj", "-subject" }, description = "Certificate subject in OpenSSL format", required = false, defaultValue = "CN=PQCLI Test Certificate, C=DE")
    private String subject;

	//public static void main(String[] args) {
    public Integer call() throws Exception {
        ProviderSetup.setupProvider();
        try {
            double validityDaysD = 0;
            try {
                validityDaysD = Double.parseDouble(validityDays);
            }
            finally {
                if (validityDaysD < 0.04) {
                    System.err.println("Error: Invalid validity period specified! Must be at least 0.04 days.");
                    return 1;
                }
            }
            subject = dnOpensslToX500(subject);

            String[] keyAlgorithms = getAlgorithmsFromStr(keyAlgorithm);
            int nKeyAlgorithms = keyAlgorithms.length;
            if (nKeyAlgorithms == 0) {
                System.err.println("Error: No key algorithm specified!");
                return 1;
            }
            if (nKeyAlgorithms > 2) {
                System.err.println("Error: More than 2 key algorithms are not supported yet!");
                return 1;
            }
            // Generate key pair(s) for the public key(s) of the certificate
            AlgorithmWithParameters keyAlgorithm = AlgorithmWithParameters.getAlgorithmParts(keyAlgorithms[0]);
            KeyPair keyPair = KeyGenerator.generateKeyPair(keyAlgorithms[0]);
            AlgorithmWithParameters altKeyAlgorithm = null;
            KeyPair altKeyPair = null;
            if (nKeyAlgorithms > 1) {
                altKeyAlgorithm = AlgorithmWithParameters.getAlgorithmParts(keyAlgorithms[1]);
                altKeyPair = KeyGenerator.generateKeyPair(keyAlgorithms[1]);
            }

            boolean isSelfSigned = true; // TODO: Only if -ca is not set

            // Generate signing key pair
            // TODO: The signing key should be importable via the -cakey option
            KeyPair signatureKeyPair, altSignatureKeyPair = null;
            if (isSelfSigned) {
                //signatureAlgorithm = getKeyAlgorithmForSignature(algorithmType);
                signatureKeyPair = keyPair;
                if (nKeyAlgorithms > 1) altSignatureKeyPair = altKeyPair;
            } else {
                signatureKeyPair = KeyGenerator.generateKeyPair(signatureAlgorithm);
            }
            signatureAlgorithm = getSuitableSignatureAlgorithm(keyAlgorithm);

            // Create X.509 certificate
            X509Certificate certificate;
            if (nKeyAlgorithms == 1) {
                certificate = generateCertificate(signatureAlgorithm, signatureKeyPair, subject, validityDaysD);
            } else {
                String altSignatureAlgorithm = getSuitableSignatureAlgorithm(altKeyAlgorithm);
                certificate = generateCertificate(signatureAlgorithm, signatureKeyPair, altSignatureAlgorithm, altSignatureKeyPair, subject, validityDaysD);
            }


            // Save certificate and key(s) to files
            KeyGenerator.saveKeyToFile("private_key.pem", keyPair.getPrivate());
            KeyGenerator.saveKeyToFile("public_key.pem", keyPair.getPublic());
            if (nKeyAlgorithms > 1) {
                KeyGenerator.saveKeyToFile("private_key_alt.pem", altKeyPair.getPrivate());
                KeyGenerator.saveKeyToFile("public_key_alt.pem", altKeyPair.getPublic());
            }
            saveCertificateToFile("certificate.pem", certificate);

            System.out.println("Certificate and key saved successfully!");
            System.out.println(certificate);

        } catch (Exception e) {
            System.err.println("Error during certificate generation: " + e.getMessage());
            e.printStackTrace();
            return 1;
        }
        return 0;
	}
	
	 private static String getSuitableSignatureAlgorithm(AlgorithmWithParameters keyAlgorithm) {
        String name = keyAlgorithm.algorithm.toLowerCase();
        String params = keyAlgorithm.keySizeOrCurve.toLowerCase();

        if (name.contains("rsa")) {
            boolean rsaPss = false;
            String sigAlgo = "SHA256withRSA";
            int keySize = Integer.parseInt(params);
            if (keySize >= 4096) {
                sigAlgo = "SHA512withRSA";
            } else if (keySize >= 3072) {
                sigAlgo = "SHA384withRSA";
            }
            if (rsaPss) sigAlgo = sigAlgo + "andMGF1";
            return sigAlgo;
        } else if (name.contains("ec")) {
            int curveSize = 256;

            // This simply takes the first number in the curve name as the curve size
            // which should be fine for all common curves but is technically hacky
            Pattern pattern = Pattern.compile("\\d+"); // One or more digits
            Matcher matcher = pattern.matcher(params);
            if (matcher.find()) {
                curveSize = Integer.parseInt(matcher.group());
            }

            // RFC 5656 section 6.2.1:
            if (curveSize > 384) {
                return "SHA512withECDSA";
            } else if (curveSize > 256) {
                return "SHA384withECDSA";
            }
            return "SHA256withECDSA";
        } else if (name.contains("ed25519")) {
            return "Ed25519";
        } else if (name.contains("ed448")) {
            return "Ed448";
        } else if (name.contains("dsa")) {
            return "SHA256withDSA";
        } else if (name.contains("dilithium")) {
            return "Dilithium"; // "ML-DSA" ok for BC 1.79+, however that does not recognize the private key
        } else if (name.contains("sphincs")) {
            return "SPHINCS+";
        }

        throw new IllegalArgumentException("No signature algorithm known for key algorithm: " + name);
    }


    /**
     * Generate a self-signed X.509 certificate.
     */
    private static X509Certificate generateCertificate(String signatureAlgorithm, KeyPair keyPair,
                                                       String altSignatureAlgo, KeyPair altKeyPair,
                                                       String subject, double validityDays)
            throws Exception {
        X500Name subjectName;
        try {
            subjectName = new X500Name(subject);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid subject name: " + e.getMessage());
        }
        X500Name issuerName = subjectName;
        BigInteger serialNumber = BigInteger.valueOf(new SecureRandom().nextInt(Integer.MAX_VALUE));
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000); // Current time - 1 day
        Date notAfter = new Date(System.currentTimeMillis() + 1000L * (long)(validityDays * 60.0 * 60.0 * 24.0)); // Current time + validityDays

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName, serialNumber, notBefore, notAfter, subjectName, keyPair.getPublic());

        // Add SubjectAltPublicKeyInfo extension for the alternative public key
        if (altKeyPair != null) {
            SubjectAltPublicKeyInfo altKeyInfo = SubjectAltPublicKeyInfo.getInstance(altKeyPair.getPublic().getEncoded());
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAltPublicKeyInfo, false, altKeyInfo);
        }

        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(keyPair.getPrivate());
        X509CertificateHolder certHolder;
        if (!altSignatureAlgo.isEmpty()) { // alternative signature algorithm is given
            ContentSigner altContentSigner = new JcaContentSignerBuilder(altSignatureAlgo).setProvider("BC").build(altKeyPair.getPrivate());
            certHolder = certBuilder.build(contentSigner, false, altContentSigner);
        } else {
            certHolder = certBuilder.build(contentSigner);
        }

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    /**
     * Generate a self-signed X.509 certificate with a single signature algorithm.
     */
    private static X509Certificate generateCertificate(String signatureAlgorithm, KeyPair keyPair, String subject, double validityDays) throws Exception {
        return generateCertificate(signatureAlgorithm, keyPair, "", null, subject, validityDays);
    }

    private static void saveCertificateToFile(String fileName, X509Certificate certificate) throws IOException, CertificateEncodingException {
        try (OutputStream os = new FileOutputStream(fileName)) {
            os.write(("-----BEGIN CERTIFICATE-----\n").getBytes());
            String encodedCert = Base64.getEncoder().encodeToString(certificate.getEncoded());
            os.write(encodedCert.getBytes());
            os.write(("\n-----END CERTIFICATE-----\n").getBytes());
        }
    }

    private static String[] getAlgorithmsFromStr(String algorithms) {
        String[] algos = algorithms.split(",");
        return Arrays.stream(algos)
                     .filter(s -> !s.trim().isEmpty()) // Remove empty and whitespace-only strings
                     .toArray(String[]::new);

    }

    // Convert OpenSSL DN (/CN=Test/C=DE) to X.500 format (CN=Test,C=DE)
    private static String dnOpensslToX500(String dn) {
        String x500Dn = dn.replace('/', ',');
        x500Dn = x500Dn.trim();
        // remove leading comma
        if (x500Dn.startsWith(",")) {
            x500Dn = x500Dn.substring(1);
        }
        return x500Dn;
    }
}
