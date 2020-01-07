package certledger;

import org.apache.commons.lang.RandomStringUtils;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static certledger.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;

public class FraudOperationsTest extends BaseCertLedgerTest {

    @Test
    public void should_report_fraud() throws Exception {
        final byte[] sslCertBytes = addSslCertificateWithChain();

        byte[] fraudId = RandomStringUtils.random(10).getBytes();
        byte[] reportFraudRequestSignature = certificateTransactionManager.generateReportFraudRequestSignatureWithRSAPSS(sslCertBytes, TEST_RSA_SSL_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        Object response = certificateTransactionManager.sendReportFraudRequest(businessSmartContractAddress, fraudId, sslCertBytes, sslCertBytes, reportFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Report Fraud Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Report Fraud Operation started",
                        "Report Fraud Operation completed",
                        "Result : true"
                );

        response = certificateTransactionManager.sendLogFraudReportStatusRequest(businessSmartContractAddress, fraudId, businessSmartContractAbiinfo);
        System.out.println("Log Fraud Report Status Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("hexValue")
                .contains(
                        "4672617564205265706f72742045786973747320696e2053746f72616765",
                        "eea4c997fd8f4702cc70db5b8c8f5d99e5755415ed0802fada10dae1911075b8",
                        "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9",
                        "00"
                );
    }

    @Test
    public void should_not_report_fraud_when_signature_is_invalid() throws Exception {
        final byte[] sslCertBytes = addSslCertificateWithChain();

        byte[] fraudId = RandomStringUtils.random(10).getBytes();
        byte[] reportFraudRequestSignature = "InvalidSignature".getBytes();
        Object response = certificateTransactionManager.sendReportFraudRequest(businessSmartContractAddress, fraudId, sslCertBytes, sslCertBytes, reportFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Report Fraud Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Report Fraud Operation started",
                        "Report Fraud Operation completed",
                        "Result : false"
                );

        response = certificateTransactionManager.sendLogFraudReportStatusRequest(businessSmartContractAddress, fraudId, businessSmartContractAbiinfo);
        System.out.println("Log Fraud Report Status Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("hexValue")
                .contains(
                        "43616e206e6f742066696e64204672617564205265706f7274"
                );
    }

    @Test
    public void should_not_report_fraud_when_domain_names_are_different() throws Exception {
        final byte[] sslCertBytes = addSslCertificateWithChain();

        byte[] fraudId = RandomStringUtils.random(10).getBytes();
        byte[] reportFraudRequestSignature = certificateTransactionManager.generateReportFraudRequestSignatureWithRSAPSS(sslCertBytes, TEST_RSA_SUB_CA_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SUB_CA_CERTIFICATE_PATH));
        Object response = certificateTransactionManager.sendReportFraudRequest(businessSmartContractAddress, fraudId, sslCertBytes, subCaCertBytes, reportFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Report Fraud Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Report Fraud Operation started",
                        "Report Fraud Operation completed",
                        "Result : false"
                );

        response = certificateTransactionManager.sendLogFraudReportStatusRequest(businessSmartContractAddress, fraudId, businessSmartContractAbiinfo);
        System.out.println("Log Fraud Report Status Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("hexValue")
                .contains(
                        "43616e206e6f742066696e64204672617564205265706f7274"
                );
    }

    private byte[] addSslCertificateWithChain() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_ROOT_CA_CERTIFICATE_PATH));
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SUB_CA_CERTIFICATE_PATH));
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SSL_CERTIFICATE_PATH));
        byte[] addRootCaRequestSignature = certificateTransactionManager.generateAddTrustedRootCACertificateRequestSignature(rootCaCertBytes);
        Object response = certificateTransactionManager.sendTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, addRootCaRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Add Root CA Certificate Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        byte[] addSubCARSAPSSRequestSignature = certificateTransactionManager.generateAddSubCARSAPSSRequestSignature(subCaCertBytes, TEST_RSA_ROOT_CA_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        response = certificateTransactionManager.sendAddSubCaCertificateRequest(businessSmartContractAddress, subCaCertBytes, addSubCARSAPSSRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Add Sub CA Certificate Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        response = certificateTransactionManager.sendAddSSLCertificateRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Add SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        return sslCertBytes;
    }

    @Test
    public void should_approve_fraud() throws Exception {
        final byte[] sslCertBytes = addSslCertificateWithChain();

        byte[] fraudId = RandomStringUtils.random(10).getBytes();
        byte[] reportFraudRequestSignature = certificateTransactionManager.generateReportFraudRequestSignatureWithRSAPSS(sslCertBytes, TEST_RSA_SSL_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        Object response = certificateTransactionManager.sendReportFraudRequest(businessSmartContractAddress, fraudId, sslCertBytes, sslCertBytes, reportFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Report Fraud Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Report Fraud Operation started",
                        "Report Fraud Operation completed",
                        "Result : true"
                );

        response = certificateTransactionManager.sendLogFraudReportStatusRequest(businessSmartContractAddress, fraudId, businessSmartContractAbiinfo);
        System.out.println("Log Fraud Report Status Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");

        byte[] approveFraudRequestSignature = certificateTransactionManager.generateApproveFraudReportRequestSignature(fraudId);
        response = certificateTransactionManager.sendApproveFraudReportRequest(businessSmartContractAddress, fraudId, approveFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Send Approve Fraud Report Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");

        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Approve Fraud Operation started",
                        "Approve Fraud Operation completed",
                        "Result : true"
                );
    }

    @Test
    public void should_not_approve_fraud_when_already_approved() throws Exception {
        final byte[] sslCertBytes = addSslCertificateWithChain();

        byte[] fraudId = RandomStringUtils.random(10).getBytes();
        byte[] reportFraudRequestSignature = certificateTransactionManager.generateReportFraudRequestSignatureWithRSAPSS(sslCertBytes, TEST_RSA_SSL_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        Object response = certificateTransactionManager.sendReportFraudRequest(businessSmartContractAddress, fraudId, sslCertBytes, sslCertBytes, reportFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Report Fraud Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Report Fraud Operation started",
                        "Report Fraud Operation completed",
                        "Result : true"
                );

        response = certificateTransactionManager.sendLogFraudReportStatusRequest(businessSmartContractAddress, fraudId, businessSmartContractAbiinfo);
        System.out.println("Log Fraud Report Status Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");

        byte[] approveFraudRequestSignature = certificateTransactionManager.generateApproveFraudReportRequestSignature(fraudId);
        response = certificateTransactionManager.sendApproveFraudReportRequest(businessSmartContractAddress, fraudId, approveFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Send Approve Fraud Report Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");

        approveFraudRequestSignature = certificateTransactionManager.generateApproveFraudReportRequestSignature(fraudId);
        response = certificateTransactionManager.sendApproveFraudReportRequest(businessSmartContractAddress, fraudId, approveFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Send Approve Fraud Report Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");

        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Approve Fraud Operation started",
                        "Invalid Fraud Report Status",
                        "Approve Fraud Operation completed",
                        "Result : false"
                );
    }

    @Test
    public void should_not_reject_fraud_when_already_rejected() throws Exception {
        final byte[] sslCertBytes = addSslCertificateWithChain();

        byte[] fraudId = RandomStringUtils.random(10).getBytes();
        byte[] reportFraudRequestSignature = certificateTransactionManager.generateReportFraudRequestSignatureWithRSAPSS(sslCertBytes, TEST_RSA_SSL_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        Object response = certificateTransactionManager.sendReportFraudRequest(businessSmartContractAddress, fraudId, sslCertBytes, sslCertBytes, reportFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Report Fraud Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");

        response = certificateTransactionManager.sendLogFraudReportStatusRequest(businessSmartContractAddress, fraudId, businessSmartContractAbiinfo);
        System.out.println("Log Fraud Report Status Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");

        byte[] rejectFraudRequestSignature = certificateTransactionManager.generateRejectFraudReportRequestSignature(fraudId);
        response = certificateTransactionManager.sendRejectFraudReportRequest(businessSmartContractAddress, fraudId, rejectFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Send Reject Fraud Report Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");

        rejectFraudRequestSignature = certificateTransactionManager.generateRejectFraudReportRequestSignature(fraudId);
        response = certificateTransactionManager.sendRejectFraudReportRequest(businessSmartContractAddress, fraudId, rejectFraudRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Send Reject Fraud Report Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");

        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Reject Fraud Operation started",
                        "Invalid Fraud Report Status",
                        "Reject Fraud Operation completed",
                        "Result : false"
                );
    }
}