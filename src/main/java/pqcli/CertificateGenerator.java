package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

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
import java.util.Base64;
import java.util.concurrent.Callable;
import java.util.Date;

@Command(name="cert", description="Generates an X.509 v3 certificate with a public/private key pair")
public class CertificateGenerator implements Callable<Integer> {

    @Option(names = { "-sig", "-s" }, description = "Signature algorithm (e.g. SHA256withRSA or SHA3-512withDilithium)")
    private String signatureAlgorithm;

    // temporary for testing, to be integrated in -sig, e.g. -sig rsa:3072 or dilithium:3
    //@Option(names = { "-siglen", "-sl" }, description = "Signature key length (e.g. 2048 for RSA signature)", required = true)
    //private String signatureKeyLength;

    @Option(names = { "-newkey", "-nk" }, description = "Key algorithm (e.g. RSA:4096, EC, DSA or Dilithium:3)", required = true)
    private String keyAlgorithm;

    //@Option(names = { "-newkeylen", "-kl" }, description = "Key length (e.g. 2048 for RSA key or 3 for Dilithium)", required = true)
    //private String keyLength;

	//public static void main(String[] args) {
    public Integer call() throws Exception {
        ProviderSetup.setupProvider();
        try {
            // BouncyCastle als Provider hinzufügen
            Security.addProvider(new BouncyCastleProvider());
            Security.addProvider(new BouncyCastlePQCProvider());

            // Debugging: Check if BouncyCastle Provider is available
            Provider provider = Security.getProvider("BCPQC");
            if (provider == null) {
                System.err.println("Error: BCPQC Provider not available!");
                return 1;
            }
            System.out.println("Successfully loaded BCPQC provider: " + provider.getInfo());

            // Generate key pair for the public key of the certificate
            KeyPair keyPair = KeyGenerator.generateKeyPair(keyAlgorithm);

            boolean isSelfSigned = true; // TODO: Only if -ca is not set

            // Generate signing key pair
            // TODO: The signing key should be importable via the -cakey option
            KeyPair signatureKeyPair;
            if (isSelfSigned) {
                //signatureAlgorithm = getKeyAlgorithmForSignature(algorithmType);
                signatureKeyPair = keyPair;
            } else {
                signatureKeyPair = KeyGenerator.generateKeyPair(signatureAlgorithm);
            }
            signatureAlgorithm = signatureKeyPair.getPrivate().getAlgorithm();

            // Zertifikat erstellen
            X509Certificate certificate = generateCertificate(signatureAlgorithm, signatureKeyPair);

            // Dateien speichern
            KeyGenerator.saveKeyToFile("private_key.pem", keyPair.getPrivate());
            KeyGenerator.saveKeyToFile("public_key.pem", keyPair.getPublic());
            saveCertificateToFile("certificate.pem", certificate);

            System.out.println("Zertifikat und Schlüssel erfolgreich gespeichert!");
            System.out.println(certificate);

        } catch (Exception e) {
            System.err.println("Error during certificate generation: " + e.getMessage());
            e.printStackTrace();
            return 1;
        }
        return 0;
	}
	
	 private static String getKeyAlgorithmForSignature(String signatureAlgorithm) {
        if (signatureAlgorithm.contains("RSA")) return "RSA";
        if (signatureAlgorithm.contains("ECDSA")) return "EC";
        if (signatureAlgorithm.contains("DSA")) return "DSA";
        if (signatureAlgorithm.contains("Dilithium")) return "Dilithium";
        throw new IllegalArgumentException("Unknown signature algorithm: " + signatureAlgorithm);
    }


    /**
     * Generiert ein selbstsigniertes X.509-Zertifikat.
     */
    private static X509Certificate generateCertificate(String signatureAlgorithm, KeyPair keyPair) throws Exception {
        X500Name issuerName = new X500Name("CN=Test Certificate, O=Example Org, C=DE");
        X500Name subjectName = issuerName;
        BigInteger serialNumber = BigInteger.valueOf(new SecureRandom().nextInt());
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000); // 1 Tag vorher
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L); // 1 Jahr gültig

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName, serialNumber, notBefore, notAfter, subjectName, keyPair.getPublic());

        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    private static void saveCertificateToFile(String fileName, X509Certificate certificate) throws IOException, CertificateEncodingException {
        try (OutputStream os = new FileOutputStream(fileName)) {
            os.write(("-----BEGIN CERTIFICATE-----\n").getBytes());
            String encodedCert = Base64.getEncoder().encodeToString(certificate.getEncoded());
            os.write(encodedCert.getBytes());
            os.write(("\n-----END CERTIFICATE-----\n").getBytes());
        }
    }
}
