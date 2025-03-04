package pqcli;
public class AlgorithmWithParameters {
    public final String algorithm;
    public final String keySizeOrCurve;

    public AlgorithmWithParameters(String algorithm, String keySizeOrCurve) {
        this.algorithm = algorithm;
        this.keySizeOrCurve = keySizeOrCurve;
    }

    public static AlgorithmWithParameters getAlgorithmParts(String algorithm) {
        String[] parts = algorithm.split(":");
        if (parts.length > 2) {
            throw new IllegalArgumentException("Invalid algorithm syntax: " + algorithm + " (Expected format: <algorithm>[:<keyLength>])");
        }
        if (parts.length == 1) {
            return new AlgorithmWithParameters(parts[0], getDefaultKeySize(parts[0]));
        }
        AlgorithmWithParameters algorithmWithParams = new AlgorithmWithParameters(parts[0], parts[1]);
        return algorithmWithParams;
    }

    private static String getDefaultKeySize(String algorithm) {
        switch (algorithm.toLowerCase()) {
            case "rsa":
                return "2048";
            case "ec":
                return "secp256r1";
            case "dsa":
                return "2048";
            case "dilithium":
                return "3";
            default:
                return ""; // Ed25519, Ed448, ...
        }
    }
}