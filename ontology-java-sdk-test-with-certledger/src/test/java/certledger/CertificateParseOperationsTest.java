package certledger;

import certledger.common.Event;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static certledger.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;

public class CertificateParseOperationsTest extends BaseCertLedgerTest {

    @Test
    public void should_parse_root_certificate() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(ONT_IO_SSL_ROOT_CA_CERT_PATH));
        Object response = certificateTransactionManager.sendParseCertificateRequest(businessSmartContractAddress, rootCaCertBytes, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Parse Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        /*"Parse Root CA Certificate started",
                        "Parse Root CA Certificate completed",
                        "true"*/
                        "Operation", "ParseCertificate"
                );
    }

    @Test
    public void should_parse_sub_ca_certificate() throws Exception {
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(ONT_IO_SSL_SUB_CA_CERT_PATH));
        Object response = certificateTransactionManager.sendParseCertificateRequest(businessSmartContractAddress, subCaCertBytes, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Parse Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                       /* "Parse Sub CA Certificate started",
                        "Parse Sub CA Certificate completed",
                        "true"
                        */
                        "Operation", "ParseCertificate"
                );
    }

    @Test
    public void should_parse_rsa_ssl_certificate() throws Exception {
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(ONT_IO_SSL_CERT_PATH));
        Object response = certificateTransactionManager.sendParseCertificateRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Parse Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        /*"Parse SSL Certificate started",
                        "Parse SSL Certificate completed",
                        "true"*/
                        "Operation", "ParseCertificate"

                );
    }

    @Test
    public void should_parse_ec_ssl_certificate() throws Exception {
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_EC_SSL_CERTIFICATE_PATH));
        Object response = certificateTransactionManager.sendParseCertificateRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Parse Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Operation", "ParseCertificate",
                        "certificate.Subject.CommonName : Test-SSL-EC-P256"
                );
    }

}