package pqcli;
public class AlgorithmWithParameters {
  public final String algorithm;
  public final String keySizeOrCurve;

  public AlgorithmWithParameters(String algorithm, String keySizeOrCurve) {
    this.algorithm = algorithm;
    this.keySizeOrCurve = keySizeOrCurve;
  }
}