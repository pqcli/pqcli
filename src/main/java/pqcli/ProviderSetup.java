package pqcli;

import java.security.*;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class ProviderSetup {
    public static int setupProvider() {
        try {
            // Add BouncyCastle as security provider
            Security.addProvider(new BouncyCastleProvider());
            Security.addProvider(new BouncyCastlePQCProvider());

            // Debugging: Check if BouncyCastle Provider is available
            Provider provider = Security.getProvider("BCPQC");
            if (provider == null) {
                System.err.println("Error: BCPQC Provider not available!");
                return 1;
            }
            System.out.println("Successfully loaded BCPQC provider: " + provider.getInfo());
        }
        catch (Exception e) {
            System.err.println("Error during provider initialization: " + e.getMessage());
            return 1;
        }
        return 0;
    }
}
