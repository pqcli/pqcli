package pqcli;

import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
    name = "pqcli",
    description = "Easy to use command line interface for Bouncy Castle for PQC certificate operations",
    mixinStandardHelpOptions = true,
    version = "PQCLI 0.1.0",
    subcommands = {
        CertificateGenerator.class,
        KeyGenerator.class,
        ViewCommand.class
    }) 
public class PqCliCommand implements Callable<Integer> {
    @Override
    public Integer call() {
        System.out.println("\r\n" + // ASCII Art
                           "   /\\   \r\n" +   //    /\
                           " /\\\\//\\ \r\n" + //  /\\//\
                           "|\\/ .\\/|\r\n" +  // |\/ .\/|
                           "| <||  |\r\n");    // | <||  |

        System.out.println("Please specify a command!");
        return 0;
    }

    public static void main(String[] args) {
      int exitCode = new CommandLine(new PqCliCommand()).execute(args);
      System.exit(exitCode);
  }
}
