package pqcli;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.Callable;

import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name="key", description="Generates a public/private key pair")
public class KeyGenerator implements Callable<Integer> {
    @Option(names = { "-newkey", "-nk", "-new", "-t" }, description = "Key algorithm (e.g. RSA:4096, EC, DSA or Dilithium:3)", required = true)
    private String keyAlgorithm;

    public Integer call() throws Exception {
        ProviderSetup.setupProvider();
        try {
            KeyPair keyPair = generateKeyPair(keyAlgorithm);

            saveKeyToFile("private_key.pem", keyPair.getPrivate());
            saveKeyToFile("public_key.pem", keyPair.getPublic());
            System.out.println("Key pair saved successfully!");
            return 0;
        } catch (Exception e) {
            System.err.println("Error during key generation: " + e.getMessage());
            return 1;
        }
    }

    public static KeyPair generateKeyPair(String algorithmAndLength) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        AlgorithmWithParameters algorithm = AlgorithmWithParameters.getAlgorithmParts(algorithmAndLength);
        return generateKeyPair(algorithm);
    }

    public static KeyPair generateKeyPair(AlgorithmWithParameters algorithm) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        if (algorithm.isComposite) {
            return generateCompositeKeyPair(algorithm);
        }
        return generateKeyPair(algorithm.algorithm, algorithm.keySizeOrCurve);
    }

    private static String[] compositeSignaturesOIDs = {
        "2.16.840.1.114027.80.8.1.21", //id-MLDSA44-RSA2048-PSS-SHA256
        "2.16.840.1.114027.80.8.1.22", //id-MLDSA44-RSA2048-PKCS15-SHA256
        "2.16.840.1.114027.80.8.1.23", //id-MLDSA44-Ed25519-SHA512
        "2.16.840.1.114027.80.8.1.24", //id-MLDSA44-ECDSA-P256-SHA256
        "2.16.840.1.114027.80.8.1.26", //id-MLDSA65-RSA3072-PSS-SHA512
        "2.16.840.1.114027.80.8.1.27", //id-MLDSA65-RSA3072-PKCS15-SHA512
        "2.16.840.1.114027.80.8.1.28", //id-MLDSA65-ECDSA-P256-SHA512
        "2.16.840.1.114027.80.8.1.29", //id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
        "2.16.840.1.114027.80.8.1.30", //id-MLDSA65-Ed25519-SHA512
        "2.16.840.1.114027.80.8.1.31", //id-MLDSA87-ECDSA-P384-SHA512
        "2.16.840.1.114027.80.8.1.32", //id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
        "2.16.840.1.114027.80.8.1.33", //id-MLDSA87-Ed448-SHA512
    };

    // see https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/internal/asn1/misc/MiscObjectIdentifiers.java#L167
    private static Map<String, String> compositeOIDLookup = Map.ofEntries(
        Map.entry("mldsa:44_rsa:2048-pss", "2.16.840.1.114027.80.8.1.21"), //id-MLDSA44-RSA2048-PSS-SHA256
        Map.entry("mldsa:44_rsa:2048", "2.16.840.1.114027.80.8.1.22"), //id-MLDSA44-RSA2048-PKCS15-SHA256
        Map.entry("mldsa:44_ed25519", "2.16.840.1.114027.80.8.1.23"), //id-MLDSA44-Ed25519-SHA512
        Map.entry("mldsa:44_ec:secp256r1", "2.16.840.1.114027.80.8.1.24"), //id-MLDSA44-ECDSA-P256-SHA256
        Map.entry("mldsa:65_rsa:3072-pss", "2.16.840.1.114027.80.8.1.26"), //id-MLDSA65-RSA3072-PSS-SHA512
        Map.entry("mldsa:65_rsa:3072", "2.16.840.1.114027.80.8.1.27"), //id-MLDSA65-RSA3072-PKCS15-SHA512
        //Map.entry("mldsa:65_rsa:3072", "2.16.840.1.114027.80.8.1.7"), //id_MLDSA65_RSA3072_PKCS15_SHA512 (BC 1.79)
        Map.entry("mldsa:65_ec:secp256r1", "2.16.840.1.114027.80.8.1.28"), //id-MLDSA65-ECDSA-P256-SHA512
        Map.entry("mldsa:65_ec:brainpoolP256r1", "2.16.840.1.114027.80.8.1.29"), //id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
        Map.entry("mldsa:65_ed25519", "2.16.840.1.114027.80.8.1.30"), //id-MLDSA65-Ed25519-SHA512
        Map.entry("mldsa:87_ec:secp384r1", "2.16.840.1.114027.80.8.1.31"), //id-MLDSA87-ECDSA-P384-SHA512
        Map.entry("mldsa:87_ec:brainpoolP384r1", "2.16.840.1.114027.80.8.1.32"), //id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
        Map.entry("mldsa:87_ed448", "2.16.840.1.114027.80.8.1.33") //id-MLDSA87-Ed448-SHA512
    );

    private static KeyPair generateCompositeKeyPair(AlgorithmWithParameters algorithm) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // String oid = compositeOIDLookup.get(algorithm);
        // if (oid == null) {
        //     throw new IllegalArgumentException("The composite algorithm " + algorithm + " is not supported.");
        // }
        KeyPair kp0 = generateKeyPair(algorithm.getCompositePart(0));
        KeyPair kp1 = generateKeyPair(algorithm.getCompositePart(1));
        CompositePrivateKey compPrivKey = new CompositePrivateKey(kp0.getPrivate(), kp1.getPrivate());
        CompositePublicKey compPubKey = new CompositePublicKey(kp0.getPublic(), kp1.getPublic());
        return new KeyPair(compPubKey, compPrivKey);
    }

    /**
     * Generates a key pair based on the given algorithm and key length.
     */
    public static KeyPair generateKeyPair(String algorithm, String curveOrKeyLength) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        curveOrKeyLength = curveOrKeyLength.toLowerCase();

        // Remove this if there is no reason to use raw Dilithium keys over ML-DSA
        if (algorithm.equals("dilithium-bcpqc")) {
            // Initialisation for PQC Algorithm CRYSTALS-Dilithium (ML-DSA / FIPS 204 is based on Dilithium)
            // Note: The Dilitium implementation in the BCPQC provider outputs a private key BC 1.79+ can no longer use for signing.
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

            // Dilithium security level (2, 3, 5 available)
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
                    throw new IllegalArgumentException("Invalid Dilithium security level " + level + ". Choose 2, 3 or 5.");
            }

            keyPairGenerator.initialize(spec, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");

        if (algorithm.equals("ec")) {
            // Initialisierung mit der angegebenen Kurve (z. B. prime256v1)
            keyPairGenerator.initialize(new ECGenParameterSpec(curveOrKeyLength), new SecureRandom());
        }
        else if (algorithm.equals("rsa")) {
            // Initialisation for RSA with the given key length
            if (curveOrKeyLength.endsWith("-pss")) { // PSS is not relevant for key generation
                curveOrKeyLength = curveOrKeyLength.substring(0, curveOrKeyLength.length() - 4);
            }
            int keyLength = Integer.parseInt(curveOrKeyLength);
            if (keyLength < 1024) {
                throw new IllegalArgumentException("RSA key length must be at least 1024 bit.");
            }
            if (keyLength % 2 != 0) {
                // enforce even key length as BC will hang unable to generate primes on odd key lengths
                throw new IllegalArgumentException("RSA key length must be an even number.");
            }
            if (keyLength > 8192) {
                // arbitrary limit, but ensures no crazy key lengths are used
                throw new IllegalArgumentException("RSA key length must be at most 8192 bit.");
            }
            if (keyLength < 2048) {
                System.out.println("Warning: RSA key length is less than 2048 bit. Consider using a stronger key length.");
            }
            keyPairGenerator.initialize(keyLength, new SecureRandom());
        }
        else if (algorithm.equals("dsa")) {
            // Initialisation for DSA with the given key length
            int keyLength = Integer.parseInt(curveOrKeyLength);
            if (keyLength < 1024 || keyLength > 4096 || keyLength % 1024 != 0) {
                throw new IllegalArgumentException("DSA key length must be either 1024, 2048, 3072, or 4096.");
            }
            keyPairGenerator.initialize(keyLength, new SecureRandom());   
        } 
        else if (algorithm.equals("mldsa")) {
            // Initialisation for PQC Algorithm ML-DSA (based on Dilithium)
            keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA", "BC");

            // Dilithium security level (2, 3, 5 available)
            int level = Integer.parseInt(curveOrKeyLength);
            MLDSAParameterSpec spec;
            switch (level) {
                case 2:
                case 44:
                    spec = MLDSAParameterSpec.ml_dsa_44;
                    break;
                case 3:
                case 65:
                    spec = MLDSAParameterSpec.ml_dsa_65;
                    break;
                case 5:
                case 87:
                    spec = MLDSAParameterSpec.ml_dsa_87; // TODO: Check if ml_dsa_87_with_sha512 should be used
                    break;
                default:
                    throw new IllegalArgumentException("Invalid ML-DSA parameter spec " + level + ". Choose 44, 65 or 87.");
            }

            keyPairGenerator.initialize(spec, new SecureRandom());
        }
        else if (algorithm.equals("slh-dsa")) {
            // Initialisation for PQC Algorithm SLH-DSA / FIPS 205 (based on SPHINCS+)
            keyPairGenerator = KeyPairGenerator.getInstance("SLH-DSA", "BC");

            // SPHINCS+ security level (128, 192, 256 available). s and f postfixes supported. SHAKE not supported for now.
            String level = curveOrKeyLength;
            SLHDSAParameterSpec spec;
            switch (level) {
                case "128":
                case "128s":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_128s; // TODO: need to use _with_sha256?
                    break;
                case "128f":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_128f;
                    break;
                case "192":
                case "192s":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_192s;
                    break;
                case "192f":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_192f;
                    break;
                case "256":
                case "256s":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_256s;
                    break;
                case "256f":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_256f;
                    break;
                default:
                    throw new IllegalArgumentException("Invalid SLH-DSA security level " + level + ". Choose 128, 192 or 256.");
            }

            keyPairGenerator.initialize(spec, new SecureRandom());
        }
        else if (algorithm.equals("ed25519") || algorithm.equals("ed448")) {
            // Initialisation for EdDSA
            keyPairGenerator.initialize(new NamedParameterSpec(algorithm), new SecureRandom());

        } else {
            throw new IllegalArgumentException("Algorithm not supported: " + algorithm);
        }

        return keyPairGenerator.generateKeyPair();
    }

    public static void saveKeyToFile(String fileName, Key key) throws IOException {
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
}
