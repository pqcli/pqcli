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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
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
            AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgorithm);

            KeyPair keyPair = generateKeyPair(algorithmSet.getAlgorithms());
            saveKeyToFile("private_key.pem", keyPair.getPrivate());
            saveKeyToFile("public_key.pem", keyPair.getPublic());
            System.out.println(keyPair);
            System.out.println("Key pair saved successfully!");

            if (algorithmSet.isHybrid()) {
                KeyPair altKeyPair = generateKeyPair(algorithmSet.getAltAlgorithms());
                saveKeyToFile("alt_private_key.pem", altKeyPair.getPrivate());
                saveKeyToFile("alt_public_key.pem", altKeyPair.getPublic());
                System.out.println(altKeyPair);
                System.out.println("Alternative key pair saved successfully!");
            }

            return 0;
        } catch (Exception e) {
            System.err.println("Error during key generation: " + e.getMessage());
            return 1;
        }
    }

    public static KeyPair generateKeyPair(AlgorithmWithParameters[] algorithms)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        if (algorithms == null || algorithms.length == 0) {
            throw new IllegalArgumentException("No algorithm specified for key generation.");
        }
        if (algorithms.length == 1) {
            return generateKeyPair(algorithms[0]);
        }
        // else: composite key
        KeyPair[] keyPairs = new KeyPair[algorithms.length];
        PrivateKey[] privateKeys = new PrivateKey[algorithms.length];
        PublicKey[] publicKeys = new PublicKey[algorithms.length];
        for (int i = 0; i < algorithms.length; i++) {
            keyPairs[i] = generateKeyPair(algorithms[i]);
            privateKeys[i] = keyPairs[i].getPrivate();
            publicKeys[i] = keyPairs[i].getPublic();
        }

        // TODO: move to CompositePrivateKey(ASN1ObjectIdentifier algorithmIdentifier, PrivateKey... keys) constructor
        // for the algorithms that have individual OIDs assigned
        CompositePrivateKey compPrivKey = new CompositePrivateKey(privateKeys);
        CompositePublicKey compPubKey = new CompositePublicKey(publicKeys);
        return new KeyPair(compPubKey, compPrivKey);
    }

    public static KeyPair generateKeyPair(AlgorithmWithParameters algorithm) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return generateKeyPair(algorithm.algorithm, algorithm.keySizeOrCurve);
    }

    /**
     * Generates a key pair based on the given algorithm and key length.
     */
    public static KeyPair generateKeyPair(String algorithm, String curveOrKeyLength) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

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
