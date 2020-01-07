package certledger;

import certledger.common.Event;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static certledger.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;

public class CertificateSignatureVerificationOperationsTest extends BaseCertLedgerTest {

    @Test
    public void should_verify_rsa_public_key_certificate_signature() throws Exception {
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SUB_CA_CERTIFICATE_PATH));
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SSL_CERTIFICATE_PATH));
        Object response = certificateTransactionManager.sendVerifyCertificateSignatureRequest(businessSmartContractAddress, sslCertBytes, subCaCertBytes, businessSmartContractAbiinfo);
        System.out.println("Verify RSA Certificate Certificate Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(response.toString());
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "VerifyCertificateSignature started",
                        "VerifyCertificateSignature finished",
                        "true"
                );
    }

    @Test
    public void should_verify_ec_public_key_certificate_signature() throws Exception {
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SUB_CA_CERTIFICATE_PATH));
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_EC_SSL_CERTIFICATE_PATH));
        Object response = certificateTransactionManager.sendVerifyCertificateSignatureRequest(businessSmartContractAddress, sslCertBytes, subCaCertBytes, businessSmartContractAbiinfo);
        System.out.println("Verify EC Certificate Certificate Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(response.toString());
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "VerifyCertificateSignature started",
                        "VerifyCertificateSignature finished",
                        "true"
                );
    }
}