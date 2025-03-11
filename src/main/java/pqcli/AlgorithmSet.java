package pqcli;

import java.util.Arrays;

/* The AlgorithmSet is capable of representing single and composite certificates.
 * Hybrid certificates are supported by the altAlgorithms field.
 * Although unlikely to be used in practice, the hybrid altSignature could be composite too.
 */
public class AlgorithmSet {
    final AlgorithmWithParameters[] algorithms;
    final AlgorithmWithParameters[] altAlgorithms;

    public AlgorithmSet(AlgorithmWithParameters[] algorithms, AlgorithmWithParameters[] altAlgorithms) {
        this.algorithms = algorithms;
        this.altAlgorithms = altAlgorithms;
    }

    public AlgorithmSet(AlgorithmWithParameters[] algorithms) {
        this(algorithms, null);
    }

    public AlgorithmSet(String algorithmStr) {
        String[] parts = algorithmStr.split(",");
        parts = Arrays.stream(parts)
            .filter(s -> !s.trim().isEmpty()) // Remove empty and whitespace-only strings
            .toArray(String[]::new);

        if (parts.length == 0) {
            throw new IllegalArgumentException("No algorithms specified");
        }

        if (parts.length > 2) {
            throw new IllegalArgumentException("Hybrid certificates cannot contain more than one alternative algorithm.");
        }

        this.algorithms = getComponents(parts[0]);
        if (parts.length == 2) {
            this.altAlgorithms = getComponents(parts[1]);
        } else {
            this.altAlgorithms = null;
        }
    }

    private static AlgorithmWithParameters[] getComponents(String componentStr) {
        String[] components = componentStr.split("_");
        components = Arrays.stream(components)
            .filter(s -> !s.trim().isEmpty()) // Remove empty and whitespace-only strings
            .toArray(String[]::new);
        AlgorithmWithParameters[] algos = new AlgorithmWithParameters[components.length];
        for (int i = 0; i < components.length; i++) {
            algos[i] = new AlgorithmWithParameters(components[i]);
        }
        return algos;
    }

    public boolean isComposite() {
        return algorithms.length > 1;
    }

    public boolean isAltComposite() {
        return altAlgorithms != null && altAlgorithms.length > 1;
    }

    public boolean isHybrid() {
        return altAlgorithms != null && altAlgorithms.length > 0;
    }

    public int numAlgorithms() {
        return algorithms.length;
    }

    public AlgorithmWithParameters getAlgorithm(int index) {
        if (index < 0 || index >= algorithms.length) {
            throw new IllegalArgumentException("Invalid index for algorithm set: " + index);
        }
        return algorithms[index];
    }

    public AlgorithmWithParameters getAlgorithm() {
        if (algorithms.length == 0) {
            throw new IllegalStateException("Set is empty");
        }
        return algorithms[0];
    }

    public AlgorithmWithParameters[] getAlgorithms() {
        return algorithms;
    }

    public AlgorithmWithParameters getAltAlgorithm(int index) {
        if (!isHybrid()) {
            throw new IllegalStateException("Not a hybrid algorithm");
        }
        if (index < 0 || index >= altAlgorithms.length) {
            throw new IllegalArgumentException("Invalid index for alt algorithm set: " + index);
        }
        return altAlgorithms[index];
    }

    public AlgorithmWithParameters getAltAlgorithm() {
        if (!isHybrid()) {
            throw new IllegalStateException("Not a hybrid algorithm");
        }
        return altAlgorithms[0];
    }

    public AlgorithmWithParameters[] getAltAlgorithms() {
        return altAlgorithms;
    }
}
