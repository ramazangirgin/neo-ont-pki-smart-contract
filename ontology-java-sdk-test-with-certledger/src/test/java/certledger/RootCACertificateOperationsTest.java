package certledger;

import certledger.common.Event;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static certledger.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

public class RootCACertificateOperationsTest extends BaseCertLedgerTest {

    @Test
    public void should_add_trusted_root_certificate() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(ONT_IO_SSL_ROOT_CA_CERT_PATH));
        byte[] addRootCaRequestSignature = certificateTransactionManager.generateAddTrustedRootCACertificateRequestSignature(rootCaCertBytes);
        Object response = certificateTransactionManager.sendTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, addRootCaRequestSignature, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Add trusted Root Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding Root CA Certificate started",
                        "Adding Root CA Certificate completed",
                        "true"
                );

        response = certificateTransactionManager.sendLogCACertificateStorageStatusRequest(businessSmartContractAddress, rootCaCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log CA Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("CA Certificate Exists in Storage", "43412043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple(null, "308203af30820297a0030201020210083be056904246b1a1756ac95991c74a300d06092a864886f70d01010505003061310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d3120301e06035504031317446967694365727420476c6f62616c20526f6f74204341301e170d3036313131303030303030305a170d3331313131303030303030305a3061310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d3120301e06035504031317446967694365727420476c6f62616c20526f6f7420434130820122300d06092a864886f70d01010105000382010f003082010a0282010100e23be11172dea8a4d3a357aa50a28f0b7790c9a2a5ee12ce965b010920cc0193a74e30b753f743c46900579de28d22dd870640008109cece1b83bfdfcd3b7146e2d666c705b37627168f7b9e1e957deeb748a308dad6af7a0c3906657f4a5d1fbc17f8abbeee28d7747f7a78995985686e5c23324bbf4ec0e85a6de370bf7710bffc01f685d9a844105832a97518d5d1a2be47e2276af49a33f84908608bd45fb43a84bfa1aa4a4c7d3ecf4f5f6c765ea04b37919edc22e66dce141a8e6acbfecdb3146417c75b299e32bff2eefad30b42d4abb74132da0cd4eff881d5bb8d583fb51be84928a270da3104ddf7b216f24c0a4e07a8ed4a3d5eb57fa390c3af270203010001a3633061300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e0416041403de503556d14cbb66f0a3e21b1bc397b23dd155301f0603551d2304183016801403de503556d14cbb66f0a3e21b1bc397b23dd155300d06092a864886f70d01010505000382010100cb9c37aa4813120afadd449c4f52b0f4dfae04f5797908a32418fc4b2b84c02db9d5c7fef4c11f58cbb86d9c7a74e79829ab11b5e370a0a1cd4c8899938c9170e2ab0f1cbe93a9ff63d5e40760d3a3bf9d5b09f1d58ee353f48e63fa3fa7dbb466df6266d6d16e418df22db5ea774a9f9d58e22b59c04023ed2d2882453e7954922698e08048a837eff0d6796016deace80ecd6eac4417382f49dae1453e2ab93653cf3a5006f72ee8c457496c612118d504ad783c2c3a806ba7ebaf1514e9d889c1b9386ce2916c8aff64b977255730c01b24a3e1dce9df477cb5b424080530ec2dbd0bbf45bf50b9a9f3eb980112adc888c698345f8d0a3cc6e9d595956dde"),
                        tuple("IsRevoked: false", "49735265766f6b65643a2066616c7365"),
                        tuple("IsTrusted: true", "4973547275737465643a2074727565")
                );
    }

    @Test
    public void should_untrust_root_certificate() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(ONT_IO_SSL_ROOT_CA_CERT_PATH));
        byte[] addRootCaRequestSignature = certificateTransactionManager.generateAddTrustedRootCACertificateRequestSignature(rootCaCertBytes);
        Object response = certificateTransactionManager.sendTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, addRootCaRequestSignature, businessSmartContractAbiinfo);
        logEvents(response.toString());
        byte[] untrustRootCACertificateRequestSignature = certificateTransactionManager.generateUntrustRootCACertificateRequestSignature(rootCaCertBytes);
        response = certificateTransactionManager.sendUnTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, untrustRootCACertificateRequestSignature, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Untrust Root Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Untrusting Root CA Certificate started",
                        "Untrusting Root CA Certificate completed",
                        "true"
                );

        response = certificateTransactionManager.sendLogCACertificateStorageStatusRequest(businessSmartContractAddress, rootCaCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log CA Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("CA Certificate Exists in Storage", "43412043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple(null, "308203af30820297a0030201020210083be056904246b1a1756ac95991c74a300d06092a864886f70d01010505003061310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d3120301e06035504031317446967694365727420476c6f62616c20526f6f74204341301e170d3036313131303030303030305a170d3331313131303030303030305a3061310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d3120301e06035504031317446967694365727420476c6f62616c20526f6f7420434130820122300d06092a864886f70d01010105000382010f003082010a0282010100e23be11172dea8a4d3a357aa50a28f0b7790c9a2a5ee12ce965b010920cc0193a74e30b753f743c46900579de28d22dd870640008109cece1b83bfdfcd3b7146e2d666c705b37627168f7b9e1e957deeb748a308dad6af7a0c3906657f4a5d1fbc17f8abbeee28d7747f7a78995985686e5c23324bbf4ec0e85a6de370bf7710bffc01f685d9a844105832a97518d5d1a2be47e2276af49a33f84908608bd45fb43a84bfa1aa4a4c7d3ecf4f5f6c765ea04b37919edc22e66dce141a8e6acbfecdb3146417c75b299e32bff2eefad30b42d4abb74132da0cd4eff881d5bb8d583fb51be84928a270da3104ddf7b216f24c0a4e07a8ed4a3d5eb57fa390c3af270203010001a3633061300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e0416041403de503556d14cbb66f0a3e21b1bc397b23dd155301f0603551d2304183016801403de503556d14cbb66f0a3e21b1bc397b23dd155300d06092a864886f70d01010505000382010100cb9c37aa4813120afadd449c4f52b0f4dfae04f5797908a32418fc4b2b84c02db9d5c7fef4c11f58cbb86d9c7a74e79829ab11b5e370a0a1cd4c8899938c9170e2ab0f1cbe93a9ff63d5e40760d3a3bf9d5b09f1d58ee353f48e63fa3fa7dbb466df6266d6d16e418df22db5ea774a9f9d58e22b59c04023ed2d2882453e7954922698e08048a837eff0d6796016deace80ecd6eac4417382f49dae1453e2ab93653cf3a5006f72ee8c457496c612118d504ad783c2c3a806ba7ebaf1514e9d889c1b9386ce2916c8aff64b977255730c01b24a3e1dce9df477cb5b424080530ec2dbd0bbf45bf50b9a9f3eb980112adc888c698345f8d0a3cc6e9d595956dde"),
                        tuple("IsRevoked: false", "49735265766f6b65643a2066616c7365"),
                        tuple("IsTrusted: false", "4973547275737465643a2066616c7365")
                );
    }

    @Test
    public void should_not_add_trusted_root_certificate_when_added_before() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(ONT_IO_SSL_ROOT_CA_CERT_PATH));
        byte[] addRootCaRequestSignature = certificateTransactionManager.generateAddTrustedRootCACertificateRequestSignature(rootCaCertBytes);
        Object response = certificateTransactionManager.sendTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, addRootCaRequestSignature, businessSmartContractAbiinfo);
        logEvents(response.toString());
        addRootCaRequestSignature = certificateTransactionManager.generateAddTrustedRootCACertificateRequestSignature(rootCaCertBytes);
        response = certificateTransactionManager.sendTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, addRootCaRequestSignature, businessSmartContractAbiinfo);
        logEvents(response.toString());
        String transactionHex = response.toString();
        System.out.println("Add trusted Root Certificate Response ( Existing )");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding Root CA Certificate started",
                        "Trusted Root CA Added Before",
                        "Adding Root CA Certificate completed",
                        "false"
                );
    }

    @Test
    public void should_not_add_trusted_root_certificate_when_request_signature_is_invalid() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(ONT_IO_SSL_ROOT_CA_CERT_PATH));
        byte[] addRootCaRequestSignature = "InvalidSignature".getBytes();
        Object response = certificateTransactionManager.sendTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, addRootCaRequestSignature, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Add trusted Root Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Adding Root CA Certificate started",
                        "Adding Root CA Certificate completed",
                        "false"
                );
    }

    @Test
    public void should_not_untrust_root_certificate_when_request_signature_is_invalid() throws Exception {
        final byte[] rootCaCertBytes = Files.readAllBytes(Paths.get(ONT_IO_SSL_ROOT_CA_CERT_PATH));
        byte[] addRootCaRequestSignature = "InvalidRequestSignature".getBytes();
        Object response = certificateTransactionManager.sendTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, addRootCaRequestSignature, businessSmartContractAbiinfo);
        logEvents(response.toString());
        byte[] untrustRootCACertificateRequestSignature = "InvalidRequestSignature".getBytes();
        response = certificateTransactionManager.sendUnTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, untrustRootCACertificateRequestSignature, businessSmartContractAbiinfo);
        String transactionHex = response.toString();
        System.out.println("Untrust Root Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        List<Event> events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue")
                .contains(
                        "Untrusting Root CA Certificate started",
                        "Untrusting Root CA Certificate completed",
                        "false"
                );
    }


    @Test
    public void should_revoke_subca_certificate_and_SSL_certificate_when_root_ca_certificate_untrusted() throws Exception {
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

        byte[] untrustRootCACertificateRequestSignature = certificateTransactionManager.generateUntrustRootCACertificateRequestSignature(rootCaCertBytes);
        response = certificateTransactionManager.sendUnTrustRootCertificateRequest(businessSmartContractAddress, rootCaCertBytes, untrustRootCACertificateRequestSignature, businessSmartContractAbiinfo);
        System.out.println("Untrust Root Certificate Response");
        System.out.println("--------------------------------");
        logEvents(response.toString());
        System.out.println("--------------------------------");
        assertThat(retrieveEvents(response.toString()))
                .extracting("stringValue")
                .contains(
                        "Untrusting Root CA Certificate started",
                        "Untrusting Root CA Certificate completed",
                        "true"
                );

        response = certificateTransactionManager.sendLogCACertificateStorageStatusRequest(businessSmartContractAddress, rootCaCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Root Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("CA Certificate Exists in Storage", "43412043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple(null, "308203c9308202b1a003020102020811e02b043c00b247300d06092a864886f70d01010b05003072310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d3131302f060355040313285465737420526f6f74202d20525341202d446967694365727420476c6f62616c20526f6f74204341301e170d3138313033313133343030305a170d3433313033313131353030305a3072310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d3131302f060355040313285465737420526f6f74202d20525341202d446967694365727420476c6f62616c20526f6f7420434130820122300d06092a864886f70d01010105000382010f003082010a0282010100df6e181e677f65103179560b5a7ac0deff98d619c15c6c7abea69c3e1c4fcf445578a4c243192f28ea6721e428840a27828ff094ed1210bdff63d83df384f41c875ff776e46a6fa5a99c9cf4c7ed79dd28e448a7a3193bf650a1b453f0b0448a706c65e5bd2dd6f2128c6b077798473b71810106083bcc7b5c98cc398ef1c5f49ee8b4beeaacea56088df48db3bd0972663cc715988af1f9d5d25768eb8caa3ee704f9189d69bbf89c34b1504f1a9e798b1d505921d963426ba68794c82aba744f16657a9cce1ac20616d5848a7441d9325148f98b9e372a1e6152fbdceff3e973042b7c2d9398bd1c6ad584e718774fe942ccad4dff3a45a8e6f7d5e9dc4adb0203010001a3633061300f0603551d130101ff040530030101ff301d0603551d0e04160414873639830c3d9317e6b459665ac93e64235069c1301f0603551d23041830168014873639830c3d9317e6b459665ac93e64235069c1300e0603551d0f0101ff040403020186300d06092a864886f70d01010b050003820101002e55ca3d8f4b1d78788a17e09ea7d5ca637c06a7fe6db4f663b73c234fb552b251eb04458d3acc967ae70275ce6df678fc5965ffe655261c8026ba135d25229bf79b8a6329e65c9ad7d672170c860720ba99f51edef4110562e8e079a0a6647ccf7a37f7f8e50594e400f1e569d02b3e5fd7e3cd3fe5138fc2534ec817a7ccf9a95ae7d01f630f08949a65814fcdd7a41f5ce4d4cb8e0115b91452ba72063edf3dfec13505f6d5393116a5f1f14b6da4dd6a464d06eb5d2ded2b3912dc71ca941cbf16c2417d7d1a4f5d884c6b4f49c2a77185f18745b77b8285450b3cc481128e93d0b061d1a6aa5049ba40da9daa32bd625facaae2dea64bd68e44f0a336e3"),
                        tuple("IsRevoked: false", "49735265766f6b65643a2066616c7365"),
                        tuple("IsTrusted: false", "4973547275737465643a2066616c7365")
                );

        response = certificateTransactionManager.sendLogCACertificateStorageStatusRequest(businessSmartContractAddress, subCaCertBytes, businessSmartContractAbiinfo);
        transactionHex = response.toString();
        System.out.println("Log Sub CA Certificate Response");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
        events = retrieveEvents(transactionHex);
        assertThat(events)
                .extracting("stringValue", "hexValue")
                .contains(
                        tuple("CA Certificate Exists in Storage", "43412043657274696669636174652045786973747320696e2053746f72616765"),
                        tuple(null, "308204a33082038ba00302010202085cbe544b138b2ab3300d06092a864886f70d01010b05003072310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d3131302f060355040313285465737420526f6f74202d20525341202d446967694365727420476c6f62616c20526f6f74204341301e170d3138313033313133353830305a170d3238313033313133353830305a307d310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d313c303a06035504031333546573742d53756243412d5253412d456e6372797074696f6e204576657279776865726520445620544c53204341202d20473130820122300d06092a864886f70d01010105000382010f003082010a0282010100be8aa7a5ff6b3ae9b21eaf3ca1d70416c6953b7f56baf2b13ffb4552a2078d3b86ee206a2871baad6e9b78843c4cd252375f1e1143c64243b63cb169d2dda9a97315a06e0e3152d10950179cbfdc9b891c4f9ce9f2c5e6e6c917e7cf0e93b0b77e69281b77adee51d341d0264f0fa5a6670848a511f79b68e56e928253fce81c4f73ffae1650c2da94fc1f5b5a5b8737fbcb5d3744916278de178169d0fc6a020a68b61646c881a56526cd55a23fb8da29a0cc903f9909ac2fd75a637a0856a33fc1fdd14604cff1a45d4951bf16b16e4174b0cc2e61e6c745fbf89cdb68ce9746d19047ad9694d5e5537c65b1b62f58fea474eb6735409846e575b862ce29eb0203010001a38201303082012c30120603551d130101ff040830060101ff020100301d0603551d0e04160414e8b02c71f1ffa7ce98c5ec5eb6dd7a5668ff7635301f0603551d23041830168014873639830c3d9317e6b459665ac93e64235069c1300e0603551d0f0101ff04040302018630420603551d1f043b30393037a035a0338631687474703a2f2f63726c332e64696769636572742e636f6d2f4469676943657274476c6f62616c526f6f7443412e63726c303406082b0601050507010104283026302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d304c0603551d2004453043303706096086480186fd6c0102302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c010201300d06092a864886f70d01010b050003820101007a91badfa7c1ff02e0ba813ee1f73ea55c048c55575108ed4d0ba4b7e2f6f888487d52a0b37d86618a64b3c5bb67e128398f5dbb1280ca99cb9d42ff505c431f5f23d2fc21bb08ea7d89b5131581fc50bf652529c28000e8c3fc396c12c7c25b2f6f25dbe931824c6cd1192cc6117da0f7f585a335c307e3452ba90040d1953638045a183d41cce3dde4d5e22177ac449ef72a1c00247bc433de5f61f808503ec39542c2ae9877645ee1ec4c29f83d53d8919c5f59c6c3927697200e0ca35058a6c769faaa20f74e4de0878eacf2afc67cda3e33738bfab3cc3a3ea981d0e437029d3bc7d2494689a7d064524a38e47107d08e39c1aa3b46d7c7859458eb6679"),
                        tuple("IsRevoked: true", "49735265766f6b65643a2074727565"),
                        tuple("IsTrusted: false", "4973547275737465643a2066616c7365")
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
    }
}