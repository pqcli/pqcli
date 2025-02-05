package com.pqcBCdemo.bouncycastleDemo;

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
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;


import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;

public class CertificateGenerator {

	public static void main(String[] args) {
        if (args.length < 4) {
            System.err.println("Usage: java -jar pqccert.jar <SignatureAlgorithm> <SignatureKeyLength> <KeyAlgorithm> <KeyLength>");
            return;
        }

        String signatureAlgorithm = args[0];      // z. B. SHA256withRSA oder SHA3-512withDilithium
        String signatureKeyLength = args[1];      // z. B. 2048 für RSA-Signatur
        String keyAlgorithm = args[2];            // z. B. RSA, EC, DSA oder Dilithium
        String keyLength = args[3];               // z. B. 2048 für RSA-Schlüssel oder 3 für Dilithium

        try {
            // BouncyCastle als Provider hinzufügen
            Security.addProvider(new BouncyCastleProvider());
            Security.addProvider(new BouncyCastlePQCProvider());

            // Debugging: Provider prüfen
            Provider provider = Security.getProvider("BCPQC");
            if (provider == null) {
                System.err.println("Fehler: BCPQC Provider nicht gefunden!");
            } else {
                System.out.println("BCPQC Provider erfolgreich geladen: " + provider.getInfo());
            }

            // Schlüsselpaar für den öffentlichen Schlüssel des Zertifikats generieren
            KeyPair keyPair = generateKeyPair(keyAlgorithm, keyLength);

            // Schlüsselpaar für die Signatur generieren
            KeyPair signatureKeyPair = generateKeyPair(getKeyAlgorithmForSignature(signatureAlgorithm), signatureKeyLength);

            // Zertifikat erstellen
            X509Certificate certificate = generateCertificate(signatureAlgorithm, signatureKeyPair);

            // Dateien speichern
            saveKeyToFile("private_key.pem", keyPair.getPrivate());
            saveKeyToFile("public_key.pem", keyPair.getPublic());
            saveCertificateToFile("certificate.pem", certificate);

            System.out.println("Zertifikat und Schlüssel erfolgreich gespeichert!");
            System.out.println(certificate);

        } catch (Exception e) {
            System.err.println("Fehler bei der Zertifikatserstellung: " + e.getMessage());
            e.printStackTrace();
        }
	}
	
	 private static String getKeyAlgorithmForSignature(String signatureAlgorithm) {
	        if (signatureAlgorithm.contains("RSA")) return "RSA";
	        if (signatureAlgorithm.contains("ECDSA")) return "EC";
	        if (signatureAlgorithm.contains("DSA")) return "DSA";
	        if (signatureAlgorithm.contains("Dilithium")) return "Dilithium";
	        throw new IllegalArgumentException("Unbekannter Signaturalgorithmus: " + signatureAlgorithm);
	    }

	
	
    /**
     * Generiert ein Schlüsselpaar basierend auf dem Algorithmus und der Schlüssellänge.
     */
    private static KeyPair generateKeyPair(String algorithm, String curveOrKeyLength) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");

        if (algorithm.equalsIgnoreCase("EC")) {
            // Initialisierung mit der angegebenen Kurve (z. B. prime256v1)
            keyPairGenerator.initialize(new ECGenParameterSpec(curveOrKeyLength), new SecureRandom());
        } else if (algorithm.equalsIgnoreCase("RSA")) {
            // Initialisierung für RSA mit der angegebenen Schlüssellänge
            int keyLength = Integer.parseInt(curveOrKeyLength);
            if (keyLength < 1024) {
                throw new IllegalArgumentException("RSA-Schlüssellänge muss mindestens 1024 Bit betragen.");
            }
            keyPairGenerator.initialize(keyLength, new SecureRandom());
        } else if (algorithm.equalsIgnoreCase("DSA")) {
            // Initialisierung für DSA mit der angegebenen Schlüssellänge
            int keyLength = Integer.parseInt(curveOrKeyLength);
            if (keyLength < 1024) {
                throw new IllegalArgumentException("DSA-Schlüssellänge muss mindestens 1024 Bit betragen.");
            }
            keyPairGenerator.initialize(keyLength, new SecureRandom());   
        } 
        else if (algorithm.equalsIgnoreCase("Dilithium")) {
            // Initialisierung für PQC-Algorithmus CRYSTALS-Dilithium
            keyPairGenerator = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

            // Wähle Dilithium-Sicherheitsstufe (2, 3, 5 verfügbar)
            int level = Integer.parseInt(curveOrKeyLength);
            DilithiumParameterSpec spec;
            switch (level) {
                case 2:
                    spec = DilithiumParameterSpec.dilithium2;
                    break;
                case 3:
                    spec = DilithiumParameterSpec.dilithium3;
                    break;
                case 5:
                    spec = DilithiumParameterSpec.dilithium5;
                    break;
                default:
                    throw new IllegalArgumentException("Ungültige Dilithium-Sicherheitsstufe. Wähle 2, 3 oder 5. Gewählt wurde " + level);
            }

            keyPairGenerator.initialize(spec, new SecureRandom());

        } else {
            throw new IllegalArgumentException("Algorithmus nicht unterstützt: " + algorithm);
        }
         
        
        
        

        return keyPairGenerator.generateKeyPair();
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

    private static void saveKeyToFile(String fileName, Key key) throws IOException {
        try (OutputStream os = new FileOutputStream(fileName)) {
            String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
            if (key instanceof PrivateKey) {
                os.write(("-----BEGIN PRIVATE KEY-----\n").getBytes());
            } else {
                os.write(("-----BEGIN PUBLIC KEY-----\n").getBytes());
            }
            os.write(encodedKey.getBytes());
            if (key instanceof PrivateKey) {
                os.write(("\n-----END PRIVATE KEY-----\n").getBytes());
            } else {
                os.write(("\n-----END PUBLIC KEY-----\n").getBytes());
            }
        }
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

