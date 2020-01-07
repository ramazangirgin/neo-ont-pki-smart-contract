package certledger;

import certledger.common.Event;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static certledger.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

public class SSLCertificateOperationsTest extends BaseCertLedgerTest {

    @Test
    public void should_add_rsa_ssl_certificate() throws Exception {
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
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "SSL Certificate process completed",
                        "Sending Notification For EVENT_NEW_SSL_CERTIFICATE_ADDED Event",
                        "Sent Notification For EVENT_NEW_SSL_CERTIFICATE_ADDED Event",
                        "true"
                );
        assertThat(events)
                .extracting("hexValue")
                .contains(
                        "4556454e545f4e4f54494649434154494f4e",
                        "4556454e545f4e45575f53534c5f43455254494649434154455f4144444544",
                        "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9"
                );

        response = certificateTransactionManager.sendLogSSLCertificateStorageStatusRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: false", "49735265766f6b65643a2066616c7365"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9")
                );

        response = certificateTransactionManager.sendLogDomainCertificatesRequest(businessSmartContractAddress, "ont.io", businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Domain Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("Log Domain Certificates started. Domain: ont.io", "4c6f6720446f6d61696e2043657274696669636174657320737461727465642e20446f6d61696e3a206f6e742e696f"),
                        tuple("Certificates for domain exists in Storage. Domain: ont.io", "43657274696669636174657320666f7220646f6d61696e2065786973747320696e2053746f726167652e20446f6d61696e3a206f6e742e696f"),
                        tuple("Certificate Count: ", "436572746966696361746520436f756e743a20"),
                        tuple("", "01"),
                        tuple("IsCa: false", "497343613a2066616c7365"),
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: false", "49735265766f6b65643a2066616c7365"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9"),
                        tuple("Log Domain Certificates completed. Domain: ont.io", "4c6f6720446f6d61696e2043657274696669636174657320636f6d706c657465642e20446f6d61696e3a206f6e742e696f")
                );

        response = certificateTransactionManager.sendLogDomainCertificatesRequest(businessSmartContractAddress, "www.ont.io", businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Domain Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("Log Domain Certificates started. Domain: www.ont.io", "4c6f6720446f6d61696e2043657274696669636174657320737461727465642e20446f6d61696e3a207777772e6f6e742e696f"),
                        tuple("Certificates for domain exists in Storage. Domain: www.ont.io", "43657274696669636174657320666f7220646f6d61696e2065786973747320696e2053746f726167652e20446f6d61696e3a207777772e6f6e742e696f"),
                        tuple("Certificate Count: ", "436572746966696361746520436f756e743a20"),
                        tuple("", "01"),
                        tuple("IsCa: false", "497343613a2066616c7365"),
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: false", "49735265766f6b65643a2066616c7365"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9"),
                        tuple("Log Domain Certificates completed. Domain: www.ont.io", "4c6f6720446f6d61696e2043657274696669636174657320636f6d706c657465642e20446f6d61696e3a207777772e6f6e742e696f")
                );
    }

    @Test
    public void should_add_ec_ssl_certificate() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_ROOT_CA_CERTIFICATE_PATH));
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SUB_CA_CERTIFICATE_PATH));
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_EC_SSL_CERTIFICATE_PATH));
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
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "SSL Certificate process completed",
                        "true"
                );

        response = certificateTransactionManager.sendLogSSLCertificateStorageStatusRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: false", "49735265766f6b65643a2066616c7365"),
                        tuple(null, "308203fb308202e3a00302010202080f63b4d306f2ad2e300d06092a864886f70d01010d0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313130333135333830305a170d3233303130333135333830305a306a310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c65204c4c433119301706035504031310546573742d53534c2d45432d503235363059301306072a8648ce3d020106082a8648ce3d030107034200040bd5fc3a13309fad24ee88186a760ae7499a42b084240c02a81bdc86999c7bc9ca27c77d1081fb18804ccbed8f744170b710bc9020182551043475ef13789e63a382015b30820157300c0603551d130101ff04023000301d0603551d0e04160414b212b670e34e59b688d5f95c90ac4645256f4394301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300b0603551d0f04040302078030130603551d25040c300a06082b0601050507030130260603551d11041f301d820d2a2e796f75747562652e636f6d820c2a2e676f6f676c652e636f6d30310603551d1f042a30283026a024a0228620687474703a2f2f63726c2e706b692e676f6f672f47545347494147332e63726c30200603551d2004193017300b06096086480186fd6c01023008060667810c010201306806082b06010505070101045c305a302d06082b060105050730028621687474703a2f2f706b692e676f6f672f677372322f47545347494147332e637274302906082b06010505073001861d687474703a2f2f6f6373702e706b692e676f6f672f4754534749414733300d06092a864886f70d01010d050003820101008a01449bdb8adede2538c3b948a233444b277fa035f63db023506ef77985949e8dc38cfe8d2c45d9bc0677574766ba4833ec4a947dcff0dbd2173848f5d2110376ac79d95de0002d168cdbd73fe9612e7bb58438da80cc5e03c07e269aadbb43b44f3905bc42cb28a326a81df6e88d523d19c52e9465496129c717b9bce6a632924b7478bfb9946eea784a1a4822a68288dbba971909f12dd4208db1600b586a623aa6ef7972ce2455d97da613de205ce11b7150e22691dbb2978cfb6bf185b184cfe5763647b2eb1c78a2dc9578e6c19c2bb7725e46cb38e79ffb4cfdd84d7867d4ba43b69730207dd599886e6c60b65f552593e39757237adda3db3d0bd150")
                );
    }

    @Test
    public void should_not_add_ssl_when_ca_not_found() throws Exception {
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(ONT_IO_SSL_CERT_PATH));
        Object response = certificateTransactionManager.sendAddSSLCertificateRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Add SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "Because of error in add in SSL Certificate Not Fee will be charged For Certificate Operation",
                        "false",
                        "SSL Certificate process completed"
                );

        response = certificateTransactionManager.sendLogSSLCertificateStorageStatusRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("SSL Certificate Not Exists in Storage", "53534c204365727469666963617465204e6f742045786973747320696e2053746f72616765")
                );

        response = certificateTransactionManager.sendLogDomainCertificatesRequest(businessSmartContractAddress, "ont.io", businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Domain Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("Log Domain Certificates started. Domain: ont.io", "4c6f6720446f6d61696e2043657274696669636174657320737461727465642e20446f6d61696e3a206f6e742e696f"),
                        tuple("There isn't any certificate for Domain: ont.io", "54686572652069736e277420616e7920636572746966696361746520666f7220446f6d61696e3a206f6e742e696f"),
                        tuple("Log Domain Certificates completed. Domain: ont.io", "4c6f6720446f6d61696e2043657274696669636174657320636f6d706c657465642e20446f6d61696e3a206f6e742e696f")
                );
    }

    @Test
    public void should_revoke_ssl_certificate_when_rsa_public_key_certificate() throws Exception {
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
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "SSL Certificate process completed",
                        "true"
                );

        byte[] revokeSSLCertificateRequestSignature = certificateTransactionManager.generateRevokeSSLCertificateRSAPSSRequestSignature(sslCertBytes, TEST_RSA_SSL_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        response = certificateTransactionManager.sendRevokeSSLCertificateRequest(businessSmartContractAddress, sslCertBytes, revokeSSLCertificateRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Revoke SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Revoke SSL Certificate started",
                        "Revoke SSL Certificate completed",
                        "Result : true"
                );

        response = certificateTransactionManager.sendLogSSLCertificateStorageStatusRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: true", "49735265766f6b65643a2074727565"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9")
                );

        response = certificateTransactionManager.sendLogDomainCertificatesRequest(businessSmartContractAddress, "ont.io", businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Domain Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("Log Domain Certificates started. Domain: ont.io", "4c6f6720446f6d61696e2043657274696669636174657320737461727465642e20446f6d61696e3a206f6e742e696f"),
                        tuple("Certificates for domain exists in Storage. Domain: ont.io", "43657274696669636174657320666f7220646f6d61696e2065786973747320696e2053746f726167652e20446f6d61696e3a206f6e742e696f"),
                        tuple("Certificate Count: ", "436572746966696361746520436f756e743a20"),
                        tuple("", "01"),
                        tuple("IsCa: false", "497343613a2066616c7365"),
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: true", "49735265766f6b65643a2074727565"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9"),
                        tuple("Log Domain Certificates completed. Domain: ont.io", "4c6f6720446f6d61696e2043657274696669636174657320636f6d706c657465642e20446f6d61696e3a206f6e742e696f")
                );

        response = certificateTransactionManager.sendLogDomainCertificatesRequest(businessSmartContractAddress, "www.ont.io", businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Domain Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("Log Domain Certificates started. Domain: www.ont.io", "4c6f6720446f6d61696e2043657274696669636174657320737461727465642e20446f6d61696e3a207777772e6f6e742e696f"),
                        tuple("Certificates for domain exists in Storage. Domain: www.ont.io", "43657274696669636174657320666f7220646f6d61696e2065786973747320696e2053746f726167652e20446f6d61696e3a207777772e6f6e742e696f"),
                        tuple("Certificate Count: ", "436572746966696361746520436f756e743a20"),
                        tuple("", "01"),
                        tuple("IsCa: false", "497343613a2066616c7365"),
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: true", "49735265766f6b65643a2074727565"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9"),
                        tuple("Log Domain Certificates completed. Domain: www.ont.io", "4c6f6720446f6d61696e2043657274696669636174657320636f6d706c657465642e20446f6d61696e3a207777772e6f6e742e696f")
                );
    }

    @Test
    public void should_revoke_ssl_certificate_when_ec_public_key_certificate() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_ROOT_CA_CERTIFICATE_PATH));
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SUB_CA_CERTIFICATE_PATH));
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_EC_SSL_CERTIFICATE_PATH));
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
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "SSL Certificate process completed",
                        "true"
                );

        byte[] revokeSSLCertificateRequestSignature = certificateTransactionManager.generateRevokeSSLCertificateECDSARequestSignature(sslCertBytes, TEST_EC_SSL_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        response = certificateTransactionManager.sendRevokeSSLCertificateRequest(businessSmartContractAddress, sslCertBytes, revokeSSLCertificateRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Revoke SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Revoke SSL Certificate started",
                        "Revoke SSL Certificate completed",
                        "Result : true"
                );

        response = certificateTransactionManager.sendLogSSLCertificateStorageStatusRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: true", "49735265766f6b65643a2074727565"),
                        tuple(null, "308203fb308202e3a00302010202080f63b4d306f2ad2e300d06092a864886f70d01010d0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313130333135333830305a170d3233303130333135333830305a306a310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c65204c4c433119301706035504031310546573742d53534c2d45432d503235363059301306072a8648ce3d020106082a8648ce3d030107034200040bd5fc3a13309fad24ee88186a760ae7499a42b084240c02a81bdc86999c7bc9ca27c77d1081fb18804ccbed8f744170b710bc9020182551043475ef13789e63a382015b30820157300c0603551d130101ff04023000301d0603551d0e04160414b212b670e34e59b688d5f95c90ac4645256f4394301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300b0603551d0f04040302078030130603551d25040c300a06082b0601050507030130260603551d11041f301d820d2a2e796f75747562652e636f6d820c2a2e676f6f676c652e636f6d30310603551d1f042a30283026a024a0228620687474703a2f2f63726c2e706b692e676f6f672f47545347494147332e63726c30200603551d2004193017300b06096086480186fd6c01023008060667810c010201306806082b06010505070101045c305a302d06082b060105050730028621687474703a2f2f706b692e676f6f672f677372322f47545347494147332e637274302906082b06010505073001861d687474703a2f2f6f6373702e706b692e676f6f672f4754534749414733300d06092a864886f70d01010d050003820101008a01449bdb8adede2538c3b948a233444b277fa035f63db023506ef77985949e8dc38cfe8d2c45d9bc0677574766ba4833ec4a947dcff0dbd2173848f5d2110376ac79d95de0002d168cdbd73fe9612e7bb58438da80cc5e03c07e269aadbb43b44f3905bc42cb28a326a81df6e88d523d19c52e9465496129c717b9bce6a632924b7478bfb9946eea784a1a4822a68288dbba971909f12dd4208db1600b586a623aa6ef7972ce2455d97da613de205ce11b7150e22691dbb2978cfb6bf185b184cfe5763647b2eb1c78a2dc9578e6c19c2bb7725e46cb38e79ffb4cfdd84d7867d4ba43b69730207dd599886e6c60b65f552593e39757237adda3db3d0bd150")
                );
    }

    @Test
    public void should_revoke_ssl_certificate_with_issuer_signed_request_when_rsa_public_key_certificate() throws Exception {
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
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "SSL Certificate process completed",
                        "true"
                );

        byte[] revokeSSLCertificateRequestSignature = certificateTransactionManager.generateRevokeSSLCertificateRSAPSSRequestSignature(sslCertBytes, TEST_RSA_SUB_CA_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        response = certificateTransactionManager.sendRevokeSSLCertificateRequest(businessSmartContractAddress, sslCertBytes, revokeSSLCertificateRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Revoke SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Revoke SSL Certificate started",
                        "Revoke SSL Certificate completed",
                        "Result : true"
                );

        response = certificateTransactionManager.sendLogSSLCertificateStorageStatusRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: true", "49735265766f6b65643a2074727565"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9")
                );

        response = certificateTransactionManager.sendLogDomainCertificatesRequest(businessSmartContractAddress, "ont.io", businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Domain Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("Log Domain Certificates started. Domain: ont.io", "4c6f6720446f6d61696e2043657274696669636174657320737461727465642e20446f6d61696e3a206f6e742e696f"),
                        tuple("Certificates for domain exists in Storage. Domain: ont.io", "43657274696669636174657320666f7220646f6d61696e2065786973747320696e2053746f726167652e20446f6d61696e3a206f6e742e696f"),
                        tuple("Certificate Count: ", "436572746966696361746520436f756e743a20"),
                        tuple("", "01"),
                        tuple("IsCa: false", "497343613a2066616c7365"),
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: true", "49735265766f6b65643a2074727565"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9"),
                        tuple("Log Domain Certificates completed. Domain: ont.io", "4c6f6720446f6d61696e2043657274696669636174657320636f6d706c657465642e20446f6d61696e3a206f6e742e696f")
                );

        response = certificateTransactionManager.sendLogDomainCertificatesRequest(businessSmartContractAddress, "www.ont.io", businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Domain Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("Log Domain Certificates started. Domain: www.ont.io", "4c6f6720446f6d61696e2043657274696669636174657320737461727465642e20446f6d61696e3a207777772e6f6e742e696f"),
                        tuple("Certificates for domain exists in Storage. Domain: www.ont.io", "43657274696669636174657320666f7220646f6d61696e2065786973747320696e2053746f726167652e20446f6d61696e3a207777772e6f6e742e696f"),
                        tuple("Certificate Count: ", "436572746966696361746520436f756e743a20"),
                        tuple("", "01"),
                        tuple("IsCa: false", "497343613a2066616c7365"),
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: true", "49735265766f6b65643a2074727565"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9"),
                        tuple("Log Domain Certificates completed. Domain: www.ont.io", "4c6f6720446f6d61696e2043657274696669636174657320636f6d706c657465642e20446f6d61696e3a207777772e6f6e742e696f")
                );
    }

    @Test
    public void should_not_revoke_ssl_certificate_when_request_signature_is_invalid() throws Exception {
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
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "SSL Certificate process completed",
                        "true"
                );

        byte[] revokeSSLCertificateRequestSignature = "InvalidRequestSignature".getBytes();
        response = certificateTransactionManager.sendRevokeSSLCertificateRequest(businessSmartContractAddress, sslCertBytes, revokeSSLCertificateRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Revoke SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Revoke SSL Certificate started",
                        "Revoke SSL Certificate completed",
                        "Result : false"
                );

        response = certificateTransactionManager.sendLogSSLCertificateStorageStatusRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: false", "49735265766f6b65643a2066616c7365"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9")
                );

        response = certificateTransactionManager.sendLogDomainCertificatesRequest(businessSmartContractAddress, "ont.io", businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Domain Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("Log Domain Certificates started. Domain: ont.io", "4c6f6720446f6d61696e2043657274696669636174657320737461727465642e20446f6d61696e3a206f6e742e696f"),
                        tuple("Certificates for domain exists in Storage. Domain: ont.io", "43657274696669636174657320666f7220646f6d61696e2065786973747320696e2053746f726167652e20446f6d61696e3a206f6e742e696f"),
                        tuple("Certificate Count: ", "436572746966696361746520436f756e743a20"),
                        tuple("", "01"),
                        tuple("IsCa: false", "497343613a2066616c7365"),
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: false", "49735265766f6b65643a2066616c7365"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9"),
                        tuple("Log Domain Certificates completed. Domain: ont.io", "4c6f6720446f6d61696e2043657274696669636174657320636f6d706c657465642e20446f6d61696e3a206f6e742e696f")
                );

        response = certificateTransactionManager.sendLogDomainCertificatesRequest(businessSmartContractAddress, "www.ont.io", businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Domain Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("Log Domain Certificates started. Domain: www.ont.io", "4c6f6720446f6d61696e2043657274696669636174657320737461727465642e20446f6d61696e3a207777772e6f6e742e696f"),
                        tuple("Certificates for domain exists in Storage. Domain: www.ont.io", "43657274696669636174657320666f7220646f6d61696e2065786973747320696e2053746f726167652e20446f6d61696e3a207777772e6f6e742e696f"),
                        tuple("Certificate Count: ", "436572746966696361746520436f756e743a20"),
                        tuple("", "01"),
                        tuple("IsCa: false", "497343613a2066616c7365"),
                        tuple("SSL Certificate Exists in Storage", "53534c2043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple("IsRevoked: false", "49735265766f6b65643a2066616c7365"),
                        tuple(null, "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9"),
                        tuple("Log Domain Certificates completed. Domain: www.ont.io", "4c6f6720446f6d61696e2043657274696669636174657320636f6d706c657465642e20446f6d61696e3a207777772e6f6e742e696f")
                );
    }

    @Test
    public void should_return_error_in_revoke_ssl_certificate_when_ssl_certificate_is_not_present() throws Exception {
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SSL_CERTIFICATE_PATH));
        byte[] revokeSSLCertificateRequestSignature = certificateTransactionManager.generateRevokeSSLCertificateRSAPSSRequestSignature(sslCertBytes, TEST_RSA_SSL_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        Object response = certificateTransactionManager.sendRevokeSSLCertificateRequest(businessSmartContractAddress, sslCertBytes, revokeSSLCertificateRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Revoke SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Revoke SSL Certificate started",
                        "Revoke SSL Certificate completed",
                        "Result : false"
                );
    }

    @Test
    public void should_not_add_ssl_certificate_when_extended_key_usage_contains_invalid_oid() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_ROOT_CA_CERTIFICATE_PATH));
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SUB_CA_CERTIFICATE_PATH));
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_INVALID_EXT_KEY_USAGE_SSL_CERTIFICATE_PATH));
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
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "Ssl Certificate Extended Key Usage Flags invalid",
                        "SSL Certificate process completed",
                        "false"
                );

        response = certificateTransactionManager.sendLogSSLCertificateStorageStatusRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("SSL Certificate Not Exists in Storage", "53534c204365727469666963617465204e6f742045786973747320696e2053746f72616765")
                );
    }

    @Test
    public void should_not_add_ssl_certificate_when_extended_key_usage_not_contain_required_oid() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_ROOT_CA_CERTIFICATE_PATH));
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SUB_CA_CERTIFICATE_PATH));
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_MISSING_REQUIRED_EXT_KEY_USAGE_SSL_CERTIFICATE_PATH));
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
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "Ssl Certificate Extended Key Usage Flags invalid",
                        "SSL Certificate process completed",
                        "false"
                );

        response = certificateTransactionManager.sendLogSSLCertificateStorageStatusRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("SSL Certificate Not Exists in Storage", "53534c204365727469666963617465204e6f742045786973747320696e2053746f72616765")
                );
    }

    @Test
    public void should_not_add_ssl_certificate_when_key_usage_extension_contains_cert_sign_or_crl_sign() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_ROOT_CA_CERTIFICATE_PATH));
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SUB_CA_CERTIFICATE_PATH));
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_INVALID_KEY_USAGE_SSL_CERTIFICATE_PATH));
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
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "End entity SSL Certificate can not have KeyCertSign or CrlSign",
                        "SSL Certificate process completed",
                        "false"
                );

        response = certificateTransactionManager.sendLogSSLCertificateStorageStatusRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("SSL Certificate Not Exists in Storage", "53534c204365727469666963617465204e6f742045786973747320696e2053746f72616765")
                );
    }

    @Test
    public void should_not_charge_fee_when_error_in_add_ssl_operation() throws Exception {
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(ONT_IO_SSL_CERT_PATH));
        Object response = certificateTransactionManager.sendAddSSLCertificateRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Add SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding SSL Certificate",
                        "Because of error in add in SSL Certificate Not Fee will be charged For Certificate Operation",
                        "SSL Certificate process completed",
                        "false"
                );
    }


    @Test
    public void should_sent_event_notification_when_ssl_certificate_added() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_ROOT_CA_CERTIFICATE_PATH));
        final byte[] subCaCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SUB_CA_CERTIFICATE_PATH));
        final byte[] sslCertBytes = Files.readAllBytes(Paths.get(TEST_RSA_SSL_CERTIFICATE_PATH));
        byte[] addRootCaRequestSignature = certificateTransactionManager.generateAddTrustedRootCACertificateRequestSignature(rootCaCertBytes);
        Object response = certificateTransactionManager.sendTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, addRootCaRequestSignature, businessSmartContractAbiinfo);
        logEvents(response.toString());
        byte[] addSubCARSAPSSRequestSignature = certificateTransactionManager.generateAddSubCARSAPSSRequestSignature(subCaCertBytes, TEST_RSA_ROOT_CA_CERTIFICATE_PRIVATE_KEY_PEM_PATH);
        response = certificateTransactionManager.sendAddSubCaCertificateRequest(businessSmartContractAddress, subCaCertBytes, addSubCARSAPSSRequestSignature, businessSmartContractAbiinfo);
        logEvents(response.toString());
        response = certificateTransactionManager.sendAddSSLCertificateRequest(businessSmartContractAddress, sslCertBytes, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Add SSL Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Sending Notification For EVENT_NEW_SSL_CERTIFICATE_ADDED Event",
                        "Sent Notification For EVENT_NEW_SSL_CERTIFICATE_ADDED Event"
                );
        assertThat(events)
                .extracting("hexValue")
                .contains(
                        "4556454e545f4e4f54494649434154494f4e",
                        "4556454e545f4e45575f53534c5f43455254494649434154455f4144444544",
                        "308205933082047ba0030201020208640d94b96e2da51a300d06092a864886f70d01010b0500307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d204731301e170d3138313033313134303530305a170d3139313033313134303530305a301a311830160603550403130f546573742d53534c2d6f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100be0f7cd1cb9b2862740c97782d839d36d008a01e5517575d1e695f1c1262a19e80d000d323427ba28c60b35f92881c250715885890d9fec0c23a65876944ed01cd7db2ee0ad396318b63cbc42e9c47504658f67565e6c3743fbe05c8a7f945c318a5772174da810e7c278996c7eebdbbec06a91c96842c1b70e12d6f44a761c654e147def5d68f68520b373481dbecc50f484a090ce07551b2bdb1e712ecc78cc24fdb2c6bc15e07a90c69aab54602f8ecddcbae484faf0069d27a8d86ebb5c9d3bbc9d0d34c3562cd41d4a6f3f3f352e2392097062f8cd2acca484862088bce8f85ca6af75c670dcb2e9893009d4863b649ed78424637fe7ddbe5cde09aad1d0203010001a38202783082027430090603551d1304023000301d0603551d0e04160414f359b1503dc5b64785307e6a485277b14157dc7e301f0603551d23041830168014e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30820105060a2b06010401d6790204020481f60481f300f1007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016667f8dab300000403004730450220398d1378fe80fd23868358e27ed4dd7f97099b31d4a5754cdfdf274317476e14022100c83cde3562790b3a257c7f47f16683c00e7bbdec7409391245c321998d6738020077008775bfe7597cf88c43995fbdf36eff568d475636ff4ab560c1b4eaff5ea0830f0000016667f8dab80000040300483046022100ca8d02ae9eb54bfb91b517f02b87218fed25d5135efdfae149d632c4f4967914022100d574e4c88b9b2d32e04e3d008c933ed6cdfe305025846350f52a400ce29ef910304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c01020130818106082b0601050507010104753073302506082b060105050730018619687474703a2f2f6f637370322e64696769636572742e636f6d304a06082b06010505073002863e687474703a2f2f636163657274732e64696769636572742e636f6d2f456e6372797074696f6e457665727977686572654456544c5343412d47312e637274300d06092a864886f70d01010b050003820101004c393b9b6d1cd2b4f989a623c1a679971c98fe3af2c929b7fb5b9be5e4cfbd999aa6449fa419f4b4c3802a6f3d224d3e33c1145b9c3c541ec7a5cb11069c0f9b596eb4aa010547e64b724e1e131c98b469718d10057bdf2d59f6a78ce8978881b0cdf4cf7362c6c72f228ff55226c66e50f82a059e4f175c0d5f54eeec29f44126359cc13fac74e3e5611acca6acfe7558340f980757d075663adefc1c547810daad5b13b9a20241036f504539e6d667954cb0306e4518e8b9067825fa0b8972de9692a7a900ae5a3503b61f7c32a893754668203ec62ec9516cffcaba9a077c08e8f4d15a5499529e27f1a312ec0fb43bbdd3276c620bff0aa1529642d523c9"
                );
    }
}