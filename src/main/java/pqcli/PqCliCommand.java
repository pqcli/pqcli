package pqcli;

import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import pqcli.CertificateGenerator;

@Command(
    name = "pqcli",
    description = "Easy to use command line interface for Bouncy Castle for PQC certificate operations",
    subcommands = {
        CertificateGenerator.class
    }) 
public class PqCliCommand implements Callable<Integer> {
    @Override
    public Integer call() {
        System.out.println("You must specify what to eat!");
        return 0;
    }

    public static void main(String[] args) {
      int exitCode = new CommandLine(new PqCliCommand()).execute(args);
      System.exit(exitCode);
  }
}
