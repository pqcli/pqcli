package pqcli;

/* Represents a single algorithm and its parameters, e. g. "rsa:2048" */
public class AlgorithmWithParameters {
    public final String algorithm;
    public final String keySizeOrCurve;

    public AlgorithmWithParameters(String algorithmStr, String keySizeOrCurve) {
        this.algorithm = normalizeAlgorithmName(algorithmStr);
        this.keySizeOrCurve = normalizeParameters(this.algorithm, keySizeOrCurve);
    }

    public AlgorithmWithParameters(String algorithmStr) {
        String[] parts = algorithmStr.split(":");
        if (parts.length != 1 && parts.length != 2) {
            throw new IllegalArgumentException("Invalid algorithm syntax: " + algorithmStr + " (Expected format: <algorithm>[:<keyLength>])");
        }
        this.algorithm = normalizeAlgorithmName(parts[0]);
        if (parts.length == 1) {
            this.keySizeOrCurve = getDefaultKeySize(this.algorithm);
        } else {
            this.keySizeOrCurve = normalizeParameters(this.algorithm, parts[1]);
        }
    }

    @Override
    public String toString() {
        return algorithm + (keySizeOrCurve.isEmpty() ? "" : ":" + keySizeOrCurve);
    }

    private static String normalizeAlgorithmName(String algorithm) {
        // Normalizes the allowed input to a single lowercase variant per algorithm
        String algo = algorithm.trim().toLowerCase();
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
                return "slh-dsa";
            default:
                System.out.println("Warning: Unrecognized algorithm: " + algo);
                return algo;
        }
    }

    private static String normalizeParameters(String algorithm, String keySizeOrCurve) {
        // Normalize parameters where multiple values refer to the same parameters
        String param = keySizeOrCurve.trim().toLowerCase();
        if (algorithm.equals("mldsa")) {
            switch (param) {
                case "2":
                    return "44";
                case "3":
                    return "65";
                case "5":
                    return "87";
                default:
                    return param;
            }
        } else if (algorithm.equals("ec")) {
            switch (param) {
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
                    return param;
            }
        }
        return param;
    }

    private static String getDefaultKeySize(String algorithm) {
        // Expects that the algorithm name is already normalized
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
            case "slh-dsa":
                return "192s";
            default:
                return ""; // Ed25519, Ed448, ...
        }
    }
}
