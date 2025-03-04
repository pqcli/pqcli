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
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid algorithm syntax: " + algorithm + " (Expected format: <algorithm>:<keyLength>)");
        }
        AlgorithmWithParameters algorithmWithParams = new AlgorithmWithParameters(parts[0], parts[1]);
        return algorithmWithParams;
    }
}