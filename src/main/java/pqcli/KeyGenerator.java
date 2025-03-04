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
import java.security.spec.EdDSAParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
import java.util.concurrent.Callable;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

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
            return 0;
        } catch (Exception e) {
            System.err.println("Error during key generation: " + e.getMessage());
            return 1;
        }
    }

    public static KeyPair generateKeyPair(String algorithmAndLength) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        AlgorithmWithParameters algorithm = AlgorithmWithParameters.getAlgorithmParts(algorithmAndLength);
        String algorithmType = algorithm.algorithm;
        String keyLength = algorithm.keySizeOrCurve;
        return generateKeyPair(algorithmType, keyLength);
    }

    /**
     * Generates a key pair based on the given algorithm and key length.
     */
    public static KeyPair generateKeyPair(String algorithm, String curveOrKeyLength) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");

        if (algorithm.equalsIgnoreCase("EC")) {
            // Initialisierung mit der angegebenen Kurve (z. B. prime256v1)
            keyPairGenerator.initialize(new ECGenParameterSpec(curveOrKeyLength), new SecureRandom());
        } else if (algorithm.equalsIgnoreCase("RSA")) {
            // Initialisation for RSA with the given key length
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
        } else if (algorithm.equalsIgnoreCase("DSA")) {
            // Initialisation for DSA with the given key length
            int keyLength = Integer.parseInt(curveOrKeyLength);
            if (keyLength < 1024 || keyLength > 4096 || keyLength % 1024 != 0) {
                throw new IllegalArgumentException("DSA key length must be either 1024, 2048, 3072, or 4096.");
            }
            keyPairGenerator.initialize(keyLength, new SecureRandom());   
        } 
        else if (algorithm.equalsIgnoreCase("Dilithium")) {
            // Initialisation for PQC-Algorithm CRYSTALS-Dilithium
            keyPairGenerator = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

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
        }
        else if (algorithm.equalsIgnoreCase("Ed25519") || algorithm.equalsIgnoreCase("Ed448")) {
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
