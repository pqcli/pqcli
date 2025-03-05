package pqcli;

import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.Callable;
import java.util.List;
import java.util.stream.Collectors;


@Command(name="view", description="View information about a certificate")
public class ViewCommand implements Callable<Integer> {
    @Parameters(index = "0", description = "The certificate file to view")
    private String certificateFile;

    @Override
    public Integer call() {
        ProviderSetup.setupProvider();
        try {
            X509Certificate cert = loadCertificate(certificateFile);
            //X509CertificateObject bcCertHolder = new X509CertificateHolder(cert.getEncoded());
            //System.out.println(bcCertHolder);
            System.out.println(cert);
        } catch (Exception e) {
            System.err.println("Error during certificate loading: " + e.getMessage());
            return 1;
        }
        return 0;
    }

    private static X509Certificate loadCertificate(String pemFilePath) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(pemFilePath));

        // check if key or certificate
        if (lines.get(0).contains("KEY---")) {
            throw new IllegalArgumentException("Viewing key data is not yet supported");
        }
        if (!lines.get(0).contains("CERTIFICATE---")) {
            throw new IllegalArgumentException("File does not appear to be a PEM-encoded certificate");
        }

        String pemContent = lines.stream()
                                 .filter(line -> !line.startsWith("-----"))
                                 .collect(Collectors.joining());

        byte[] decoded = Base64.getDecoder().decode(pemContent);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decoded));
    }

}
