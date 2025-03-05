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
import java.util.stream.Collectors;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.X509CertificateObject;

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
        String pemContent = Files.readAllLines(Paths.get(pemFilePath))
                                 .stream()
                                 .filter(line -> !line.startsWith("-----"))
                                 .collect(Collectors.joining());

        byte[] decoded = Base64.getDecoder().decode(pemContent);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decoded));
    }

}
