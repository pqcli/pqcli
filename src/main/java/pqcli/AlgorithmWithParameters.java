package pqcli;
public class AlgorithmWithParameters {
    public final String algorithm;
    public final String keySizeOrCurve;
    public final boolean isComposite;

    public AlgorithmWithParameters(String algorithm, String keySizeOrCurve) {
        this.algorithm = algorithm;
        this.keySizeOrCurve = normalizeParameters(algorithm, keySizeOrCurve);
        this.isComposite = algorithm.contains("_");
    }

    public static AlgorithmWithParameters getAlgorithmParts(String algorithm) {
        if (algorithm.contains("_")) {
            // is composite algorithm, e.g "mldsa:65_rsa:3072", need to normalize left and right components separately
            String[] components = algorithm.split("_");
            if (components.length != 2) {
                throw new IllegalArgumentException("Invalid composite algorithm syntax: " + algorithm + " (Expected format: <algorithm>[:<keyLength>]_<algorithm2>[:<keyLength2>])");
            }
            AlgorithmWithParameters left = getAlgorithmParts(components[0]);
            AlgorithmWithParameters right = getAlgorithmParts(components[1]);
            return new AlgorithmWithParameters(left.toString() + "_" + right.toString(), "");
        }
        String[] parts = algorithm.split(":");
        if (parts.length > 2) {
            throw new IllegalArgumentException("Invalid algorithm syntax: " + algorithm + " (Expected format: <algorithm>[:<keyLength>])");
        }
        parts[0] = normalizeAlgorithmName(parts[0]);
        if (parts.length == 1) {
            return new AlgorithmWithParameters(parts[0], getDefaultKeySize(parts[0]));
        }
        AlgorithmWithParameters algorithmWithParams = new AlgorithmWithParameters(parts[0], parts[1]);
        return algorithmWithParams;
    }

    @Override
    public String toString() {
        return algorithm + (keySizeOrCurve.isEmpty() ? "" : ":" + keySizeOrCurve);
    }

    private static String normalizeAlgorithmName(String algorithm) {
        // Normalizes the allowed input to a single lowercase variant per algorithm
        String algo = algorithm.toLowerCase();
        switch (algo) {
            case "rsa":
            case "ec":
            case "dsa":
            case "ed25519":
            case "ed448":
            case "dilithium-bcpqc":
                return algo;
            case "dilithium":
            case "mldsa":
            case "ml-dsa":
                return "mldsa";
            case "slhdsa":
            case "slh-dsa":
            case "sphincs":
            case "sphincs+":
            case "sphincsplus":
                return "slhdsa";
            default:
                System.out.println("Warning: Unrecognized algorithm: " + algo);
                return algo;
        }
    }

    private static String normalizeParameters(String algorithm, String keySizeOrCurve) {
        // Normalize parameters where multiple values refer to the same parameters
        if (algorithm.equals("mldsa")) {
            switch (keySizeOrCurve) {
                case "2":
                    return "44";
                case "3":
                    return "65";
                case "5":
                    return "87";
                default:
                    return keySizeOrCurve;
            }
        } else if (algorithm.equals("ec")) {
            switch (keySizeOrCurve) {
                case "secp256r1":
                case "nistp256":
                case "p256":
                case "p-256":
                case "prime256v1":
                    return "secp256r1";
                case "secp384r1":
                case "nistp384":
                case "p384":
                case "p-384":
                    return "secp384r1";
                case "secp521r1":
                case "nistp521":
                case "p521":
                case "p-521":
                    return "secp521r1";
                default:
                    return keySizeOrCurve;
            }
        }
        return keySizeOrCurve;
    }

    private static String getDefaultKeySize(String algorithm) {
        switch (algorithm) {
            case "rsa":
                return "3072";
            case "ec":
                return "secp256r1";
            case "dsa":
                return "2048";
            case "dilithium-bcpqc":
                return "3";
            case "mldsa":
                return "65";
            case "slhdsa":
                return "192";
            default:
                return ""; // Ed25519, Ed448, ...
        }
    }
}