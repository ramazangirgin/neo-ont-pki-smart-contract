using System;
using System.IO;
using CertLedgerBusinessSCTemplate.src.io.certledger;
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract;
using io.certledger.smartcontract.platform.netcore;
using Org.BouncyCastle.Security;
using Xunit;

namespace CertLedgerTestProject
{
    public class CertificateParserTest
    {
        public CertificateParserTest()
        {
            StorageUtil.clearStorage();
        }

        [Fact]
        public void Should_Parse_Verisign_Class_3_Root_CA_Certificate()
        {
            string rootCertFilePath =
                "../../../test-data/certs/www.ont.io/VeriSign Class 3 Public Primary Certification Authority - G5.cer";
            byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
            var rootCertEncodedHex = HexUtil.ConvertByteArrayToHexString(rootCertEncoded);
            byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);

            Certificate certificate = CertificateParser.Parse(rootCertEncoded);

            Assert.Equal(
                "308204d3308203bba003020102021018dad19e267de8bb4a2158cdcc6b3b4a300d06092a864886f70d01010505003081ca310b300906035504061302555331173015060355040a130e566572695369676e2c20496e632e311f301d060355040b1316566572695369676e205472757374204e6574776f726b313a3038060355040b1331286329203230303620566572695369676e2c20496e632e202d20466f7220617574686f72697a656420757365206f6e6c79314530430603550403133c566572695369676e20436c6173732033205075626c6963205072696d6172792043657274696669636174696f6e20417574686f72697479202d204735301e170d3036313130383030303030305a170d3336303731363233353935395a3081ca310b300906035504061302555331173015060355040a130e566572695369676e2c20496e632e311f301d060355040b1316566572695369676e205472757374204e6574776f726b313a3038060355040b1331286329203230303620566572695369676e2c20496e632e202d20466f7220617574686f72697a656420757365206f6e6c79314530430603550403133c566572695369676e20436c6173732033205075626c6963205072696d6172792043657274696669636174696f6e20417574686f72697479202d20473530820122300d06092a864886f70d01010105000382010f003082010a0282010100af240808297a359e600caae74b3b4edc7cbc3c451cbb2be0fe2902f95708a364851527f5f1adc831895d22e82aaaa642b38ff8b955b7b1b74bb3fe8f7e0757ecef43db66621561cf600da4d8def8e0c362083d5413eb49ca59548526e52b8f1b9febf5a191c23349d843636a524bd28fe870514dd189697bc770f6b3dc1274db7b5d4b56d396bf1577a1b0f4a225f2af1c926718e5f40604ef90b9e400e4dd3ab519ff02baf43ceee08beb378becf4d7acf2f6f03dafdd759133191d1c40cb7424192193d914feac2a52c78fd50449e48d6347883c6983cbfe47bd2b7e4fc595ae0e9dd4d143c06773e314087ee53f9f73b8330acf5d3f3487968aee53e825150203010001a381b23081af300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106306d06082b0601050507010c0461305fa15da05b3059305730551609696d6167652f6769663021301f300706052b0e03021a04148fe5d31a86ac8d8e6bc3cf806ad448182c7b192e30251623687474703a2f2f6c6f676f2e766572697369676e2e636f6d2f76736c6f676f2e676966301d0603551d0e041604147fd365a7c2ddecbbf03009f34339fa02af333133300d06092a864886f70d0101050500038201010093244a305f62cfd81a982f3deadc992dbd77f6a5792238ecc4a7a07812ad620e457064c5e797662d98097e5fafd6cc2865f201aa081a47def9f97c925a0869200dd93e6d6e3c0d6ed8e606914018b9f8c1eddfdb41aae09620c9cd64153881c994eea284290b136f8edb0cdd2502dba48b1944d2417a05694a584f60ca7e826a0b02aa251739b5db7fe784652a958abd86de5e8116832d10ccdefda8822a6d281f0d0bc4e5e71a2619e1f4116f10b595fce7420532dbce9d515e28b69e85d35befa57d4540728eb70e6b0e06fb33354871b89d278bc4655f0d86769c447af6955cf65d320833a454b6183f685cf2424a853854835fd1e82cf2ac11d6a8ed636a",
                rootCertEncodedHex);
            Assert.Equal("9acfab7e43c8d880d06b262a94deeee4b4659989c3d0caf19baf6405e41ab7df",
                HexUtil.ConvertByteArrayToHexString(rootCertDigest));
            Assert.Equal(true, certificate.IsLoaded);
            Assert.Equal(3, certificate.Version);
            Assert.Equal("18dad19e267de8bb4a2158cdcc6b3b4a",
                HexUtil.ConvertByteArrayToHexString(certificate.SerialNumber.ToByteArray()));
            Assert.Equal(true, certificate.BasicConstraints.HasBasicConstraints);
            Assert.Equal(true, certificate.BasicConstraints.IsCa);
            Assert.Equal(false, certificate.BasicConstraints.HasPathLengthConstraint);
            Assert.Equal(0, certificate.BasicConstraints.MaxPathLen);
            string subjectPublicKeyInfoHex = HexUtil.ConvertByteArrayToHexString(certificate.SubjectPublicKeyInfo);
            Assert.Equal(
                "30820122300d06092a864886f70d01010105000382010f003082010a0282010100af240808297a359e600caae74b3b4edc7cbc3c451cbb2be0fe2902f95708a364851527f5f1adc831895d22e82aaaa642b38ff8b955b7b1b74bb3fe8f7e0757ecef43db66621561cf600da4d8def8e0c362083d5413eb49ca59548526e52b8f1b9febf5a191c23349d843636a524bd28fe870514dd189697bc770f6b3dc1274db7b5d4b56d396bf1577a1b0f4a225f2af1c926718e5f40604ef90b9e400e4dd3ab519ff02baf43ceee08beb378becf4d7acf2f6f03dafdd759133191d1c40cb7424192193d914feac2a52c78fd50449e48d6347883c6983cbfe47bd2b7e4fc595ae0e9dd4d143c06773e314087ee53f9f73b8330acf5d3f3487968aee53e825150203010001",
                subjectPublicKeyInfoHex);
            Assert.Equal("5253412f2f504b43533150414444494e47",
                HexUtil.ConvertByteArrayToHexString(certificate.PublicKeyAlgName));
            var signatureAlgorithmHex = HexUtil.ConvertByteArrayToHexString(certificate.SignatureAlgorithm);
            Assert.Equal("300d06092a864886f70d0101050500", signatureAlgorithmHex);

            Assert.True(certificate.KeyUsage.HasKeyUsageExtension);
            Assert.True(certificate.KeyUsage.IsCritical);
            Assert.True((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyCertSign) != 0);
            Assert.True((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.CrlSign) != 0);
            Assert.True((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.None) == 0);
            Assert.True((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.EncipherOnly) == 0);
            Assert.True((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyAgreement) == 0);
            Assert.True((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.DataEncipherment) == 0);
            Assert.True((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyEncipherment) == 0);
            Assert.True((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.DigitalSignature) == 0);
            Assert.True((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.DecipherOnly) == 0);

            Assert.True(certificate.SubjectKeyIdentifier.HasSubjectKeyIdentifierExtension);
            Assert.False(certificate.SubjectKeyIdentifier.IsCritical);
            Assert.Equal(HexUtil.HexStringToByteArray("7FD365A7C2DDECBBF03009F34339FA02AF333133"),
                certificate.SubjectKeyIdentifier.keyIdentifier);

            Assert.Null(certificate.AuthorityKeyIdentifier.keyIdentifier);

            Assert.Equal(1162944000, certificate.Validity.NotBefore);
            Assert.Equal(2099865599, certificate.Validity.NotAfter);
            Assert.False(certificate.ExtendedKeyUsage.HasExtendedKeyUsageExtension);

            string TbsCertificateHex = HexUtil.ConvertByteArrayToHexString(certificate.TbsCertificate);
            Assert.Equal(
                "308203bba003020102021018dad19e267de8bb4a2158cdcc6b3b4a300d06092a864886f70d01010505003081ca310b300906035504061302555331173015060355040a130e566572695369676e2c20496e632e311f301d060355040b1316566572695369676e205472757374204e6574776f726b313a3038060355040b1331286329203230303620566572695369676e2c20496e632e202d20466f7220617574686f72697a656420757365206f6e6c79314530430603550403133c566572695369676e20436c6173732033205075626c6963205072696d6172792043657274696669636174696f6e20417574686f72697479202d204735301e170d3036313130383030303030305a170d3336303731363233353935395a3081ca310b300906035504061302555331173015060355040a130e566572695369676e2c20496e632e311f301d060355040b1316566572695369676e205472757374204e6574776f726b313a3038060355040b1331286329203230303620566572695369676e2c20496e632e202d20466f7220617574686f72697a656420757365206f6e6c79314530430603550403133c566572695369676e20436c6173732033205075626c6963205072696d6172792043657274696669636174696f6e20417574686f72697479202d20473530820122300d06092a864886f70d01010105000382010f003082010a0282010100af240808297a359e600caae74b3b4edc7cbc3c451cbb2be0fe2902f95708a364851527f5f1adc831895d22e82aaaa642b38ff8b955b7b1b74bb3fe8f7e0757ecef43db66621561cf600da4d8def8e0c362083d5413eb49ca59548526e52b8f1b9febf5a191c23349d843636a524bd28fe870514dd189697bc770f6b3dc1274db7b5d4b56d396bf1577a1b0f4a225f2af1c926718e5f40604ef90b9e400e4dd3ab519ff02baf43ceee08beb378becf4d7acf2f6f03dafdd759133191d1c40cb7424192193d914feac2a52c78fd50449e48d6347883c6983cbfe47bd2b7e4fc595ae0e9dd4d143c06773e314087ee53f9f73b8330acf5d3f3487968aee53e825150203010001a381b23081af300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106306d06082b0601050507010c0461305fa15da05b3059305730551609696d6167652f6769663021301f300706052b0e03021a04148fe5d31a86ac8d8e6bc3cf806ad448182c7b192e30251623687474703a2f2f6c6f676f2e766572697369676e2e636f6d2f76736c6f676f2e676966301d0603551d0e041604147fd365a7c2ddecbbf03009f34339fa02af333133",
                TbsCertificateHex);

            string tBSSignatureAlgorithmHex = HexUtil.ConvertByteArrayToHexString(certificate.TBSSignatureAlgorithm);
            Assert.Equal(
                "300d06092a864886f70d0101050500",
                tBSSignatureAlgorithmHex);

            var signatureHex = HexUtil.ConvertByteArrayToHexString(certificate.Signature);
            Assert.Equal(
                "93244a305f62cfd81a982f3deadc992dbd77f6a5792238ecc4a7a07812ad620e457064c5e797662d98097e5fafd6cc2865f201aa081a47def9f97c925a0869200dd93e6d6e3c0d6ed8e606914018b9f8c1eddfdb41aae09620c9cd64153881c994eea284290b136f8edb0cdd2502dba48b1944d2417a05694a584f60ca7e826a0b02aa251739b5db7fe784652a958abd86de5e8116832d10ccdefda8822a6d281f0d0bc4e5e71a2619e1f4116f10b595fce7420532dbce9d515e28b69e85d35befa57d4540728eb70e6b0e06fb33354871b89d278bc4655f0d86769c447af6955cf65d320833a454b6183f685cf2424a853854835fd1e82cf2ac11d6a8ed636a",
                signatureHex);

            string subjectCNHex = HexUtil.ConvertByteArrayToHexString(certificate.Subject.CommonName);
            Assert.Equal(
                "566572695369676e20436c6173732033205075626c6963205072696d6172792043657274696669636174696f6e20417574686f72697479202d204735",
                subjectCNHex);

            string issuerCNHex = HexUtil.ConvertByteArrayToHexString(certificate.Issuer.CommonName);
            Assert.Equal(
                "566572695369676e20436c6173732033205075626c6963205072696d6172792043657274696669636174696f6e20417574686f72697479202d204735",
                issuerCNHex);

            Assert.Null(certificate.DNsNames);
        }

        [Fact]
        public void Should_Parse_Symantec_SSL_SubCA_Certificate()
        {
            string subCaCertFilePath = "../../../test-data/certs/www.ont.io/Symantec Basic DV SSL CA - G1.cer";
            byte[] subCaCertEncoded = File.ReadAllBytes(subCaCertFilePath);
            var subCaCertEncodedHex = HexUtil.ConvertByteArrayToHexString(subCaCertEncoded);
            Certificate subCaCertificate = CertificateParser.Parse(subCaCertEncoded);

            String subCaCertDigestHex =
                HexUtil.ConvertByteArrayToHexString(DigestUtilities.CalculateDigest("SHA_256", subCaCertEncoded));
            Assert.Equal("526e30ded6bf9d5ce216f50c832402b48ab70d55aeda918a1873a5883ebdb1b5", subCaCertDigestHex);

            Assert.Equal(
                "308205623082044aa00302010202104c4cd8a0fc4feaae1554a87f090eda87300d06092a864886f70d01010b05003081ca310b300906035504061302555331173015060355040a130e566572695369676e2c20496e632e311f301d060355040b1316566572695369676e205472757374204e6574776f726b313a3038060355040b1331286329203230303620566572695369676e2c20496e632e202d20466f7220617574686f72697a656420757365206f6e6c79314530430603550403133c566572695369676e20436c6173732033205075626c6963205072696d6172792043657274696669636174696f6e20417574686f72697479202d204735301e170d3136303630373030303030305a170d3236303630363233353935395a308194310b3009060355040613025553311d301b060355040a131453796d616e74656320436f72706f726174696f6e311f301d060355040b131653796d616e746563205472757374204e6574776f726b311d301b060355040b1314446f6d61696e2056616c6964617465642053534c312630240603550403131d53796d616e7465632042617369632044562053534c204341202d20473130820122300d06092a864886f70d01010105000382010f003082010a0282010100a437c858ca5ad90998a1660376e45b224fea9f3aff2b2a2dcc6d122c6764d4aac4b97b57832cf5c8f083f85d75192d6b7d865aa60e9aa265ae662d20632835f7896abf15a39cf25d40b1b78e86bf591120a8128aea9ba4bdc002fe1d7ee12d8ffba74dd248d4803befe0af6a3b7225aede385df87e1dcc634d0cdd270ae448397eeb4c6608e6639bf10589442e87ff7325518a41b7d555fa5d8554d8412c9ba87c5dd3349a23547c629999d3124c9b83fafd0197364e40c7257d4103aacd8d71bc97989208bf4808908150f079cffb3785005090e00b5cdf3c41322b963e775e95a9ab161d409ace15bb568b5f165b76409c602c71df2f67950883728b026a010203010001a38201763082017230120603551d130101ff040830060101ff020100302f0603551d1f042830263024a022a020861e687474703a2f2f732e73796d63622e636f6d2f706361332d67352e63726c300e0603551d0f0101ff040403020106302e06082b0601050507010104223020301e06082b060105050730018612687474703a2f2f732e73796d63642e636f6d30610603551d20045a30583056060667810c010201304c302306082b06010505070201161768747470733a2f2f642e73796d63622e636f6d2f637073302506082b0601050507020230191a1768747470733a2f2f642e73796d63622e636f6d2f727061301d0603551d250416301406082b0601050507030106082b0601050507030230290603551d1104223020a41e301c311a30180603550403131153796d616e746563504b492d322d353535301d0603551d0e041604145c619eb07641a96aaa430be1c76e30296eb1cd36301f0603551d230418301680147fd365a7c2ddecbbf03009f34339fa02af333133300d06092a864886f70d01010b0500038201010061ea45712f8de13f0a9b9548f1f23ca25816ca96c4ffdae2ab97711091b32fa48b810ff2a4fb35f3e7904a20c59be531cb47b1681db536e9f528576ea0a7a973c2c39ef90591f6ac428dc48df4096afa538ee7e21da14a7689c4979e03ec4ab00d55938bfc78bbbbc7046507085912c60d1405690f76044e87a41fcefb43366b67a11d1bfdd583ab1db470d0e22fd4f3bb324e6c8cda5f2f5ce1886437755abe9da9e7b616d09f86f01c58c6ef87f27ab0138732ad159f91bc4e9ea2530b11958d73ecb69028096794e8a26558617bed60bf32411c2d2df87af6d981f06a82832e1481d05fe01a4ce2350fa9cb58459dee0c10ebafccec49a639f4fb04486c19",
                subCaCertEncodedHex);
            Assert.Equal(
                "4c4cd8a0fc4feaae1554a87f090eda87",
                HexUtil.ConvertByteArrayToHexString(subCaCertificate.SerialNumber.ToByteArray()));

            Assert.Equal(3, subCaCertificate.Version);
            Assert.Equal(true, subCaCertificate.BasicConstraints.HasBasicConstraints);
            Assert.Equal(true, subCaCertificate.BasicConstraints.IsCa);
            Assert.Equal(true, subCaCertificate.BasicConstraints.HasPathLengthConstraint);
            Assert.Equal(0, subCaCertificate.BasicConstraints.MaxPathLen);
            string subjectPublicKeyInfoHex = HexUtil.ConvertByteArrayToHexString(subCaCertificate.SubjectPublicKeyInfo);
            Assert.Equal(
                "30820122300d06092a864886f70d01010105000382010f003082010a0282010100a437c858ca5ad90998a1660376e45b224fea9f3aff2b2a2dcc6d122c6764d4aac4b97b57832cf5c8f083f85d75192d6b7d865aa60e9aa265ae662d20632835f7896abf15a39cf25d40b1b78e86bf591120a8128aea9ba4bdc002fe1d7ee12d8ffba74dd248d4803befe0af6a3b7225aede385df87e1dcc634d0cdd270ae448397eeb4c6608e6639bf10589442e87ff7325518a41b7d555fa5d8554d8412c9ba87c5dd3349a23547c629999d3124c9b83fafd0197364e40c7257d4103aacd8d71bc97989208bf4808908150f079cffb3785005090e00b5cdf3c41322b963e775e95a9ab161d409ace15bb568b5f165b76409c602c71df2f67950883728b026a010203010001",
                subjectPublicKeyInfoHex);
            Assert.Equal("5253412f2f504b43533150414444494e47",
                HexUtil.ConvertByteArrayToHexString(subCaCertificate.PublicKeyAlgName));
            Assert.Equal("300d06092a864886f70d01010b0500",
                HexUtil.ConvertByteArrayToHexString(subCaCertificate.SignatureAlgorithm));

            Assert.True(subCaCertificate.KeyUsage.HasKeyUsageExtension);
            Assert.True(subCaCertificate.KeyUsage.IsCritical);
            Assert.True((subCaCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyCertSign) != 0);
            Assert.True((subCaCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.CrlSign) != 0);
            Assert.True((subCaCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.None) == 0);
            Assert.True((subCaCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.EncipherOnly) == 0);
            Assert.True((subCaCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyAgreement) == 0);
            Assert.True((subCaCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.DataEncipherment) == 0);
            Assert.True((subCaCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyEncipherment) == 0);
            Assert.True((subCaCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.DigitalSignature) == 0);
            Assert.True((subCaCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.DecipherOnly) == 0);

            Assert.True(subCaCertificate.SubjectKeyIdentifier.HasSubjectKeyIdentifierExtension);
            Assert.False(subCaCertificate.SubjectKeyIdentifier.IsCritical);
            Assert.Equal(HexUtil.HexStringToByteArray("5C619EB07641A96AAA430BE1C76E30296EB1CD36"),
                subCaCertificate.SubjectKeyIdentifier.keyIdentifier);

            Assert.True(subCaCertificate.AuthorityKeyIdentifier.HasAuthorityKeyIdentifier);
            Assert.False(subCaCertificate.AuthorityKeyIdentifier.IsCritical);
            Assert.Equal("7fd365a7c2ddecbbf03009f34339fa02af333133",
                HexUtil.ConvertByteArrayToHexString(subCaCertificate.AuthorityKeyIdentifier.keyIdentifier));

            Assert.Equal(1465257600, subCaCertificate.Validity.NotBefore);
            Assert.Equal(1780790399, subCaCertificate.Validity.NotAfter);
            Assert.True(subCaCertificate.ExtendedKeyUsage.HasExtendedKeyUsageExtension);

            string TbsCertificateHex = HexUtil.ConvertByteArrayToHexString(subCaCertificate.TbsCertificate);
            Assert.Equal(
                "3082044aa00302010202104c4cd8a0fc4feaae1554a87f090eda87300d06092a864886f70d01010b05003081ca310b300906035504061302555331173015060355040a130e566572695369676e2c20496e632e311f301d060355040b1316566572695369676e205472757374204e6574776f726b313a3038060355040b1331286329203230303620566572695369676e2c20496e632e202d20466f7220617574686f72697a656420757365206f6e6c79314530430603550403133c566572695369676e20436c6173732033205075626c6963205072696d6172792043657274696669636174696f6e20417574686f72697479202d204735301e170d3136303630373030303030305a170d3236303630363233353935395a308194310b3009060355040613025553311d301b060355040a131453796d616e74656320436f72706f726174696f6e311f301d060355040b131653796d616e746563205472757374204e6574776f726b311d301b060355040b1314446f6d61696e2056616c6964617465642053534c312630240603550403131d53796d616e7465632042617369632044562053534c204341202d20473130820122300d06092a864886f70d01010105000382010f003082010a0282010100a437c858ca5ad90998a1660376e45b224fea9f3aff2b2a2dcc6d122c6764d4aac4b97b57832cf5c8f083f85d75192d6b7d865aa60e9aa265ae662d20632835f7896abf15a39cf25d40b1b78e86bf591120a8128aea9ba4bdc002fe1d7ee12d8ffba74dd248d4803befe0af6a3b7225aede385df87e1dcc634d0cdd270ae448397eeb4c6608e6639bf10589442e87ff7325518a41b7d555fa5d8554d8412c9ba87c5dd3349a23547c629999d3124c9b83fafd0197364e40c7257d4103aacd8d71bc97989208bf4808908150f079cffb3785005090e00b5cdf3c41322b963e775e95a9ab161d409ace15bb568b5f165b76409c602c71df2f67950883728b026a010203010001a38201763082017230120603551d130101ff040830060101ff020100302f0603551d1f042830263024a022a020861e687474703a2f2f732e73796d63622e636f6d2f706361332d67352e63726c300e0603551d0f0101ff040403020106302e06082b0601050507010104223020301e06082b060105050730018612687474703a2f2f732e73796d63642e636f6d30610603551d20045a30583056060667810c010201304c302306082b06010505070201161768747470733a2f2f642e73796d63622e636f6d2f637073302506082b0601050507020230191a1768747470733a2f2f642e73796d63622e636f6d2f727061301d0603551d250416301406082b0601050507030106082b0601050507030230290603551d1104223020a41e301c311a30180603550403131153796d616e746563504b492d322d353535301d0603551d0e041604145c619eb07641a96aaa430be1c76e30296eb1cd36301f0603551d230418301680147fd365a7c2ddecbbf03009f34339fa02af333133",
                TbsCertificateHex);

            string tBSSignatureAlgorithmHex =
                HexUtil.ConvertByteArrayToHexString(subCaCertificate.TBSSignatureAlgorithm);
            Assert.Equal(
                "300d06092a864886f70d01010b0500",
                tBSSignatureAlgorithmHex);

            var signatureHex = HexUtil.ConvertByteArrayToHexString(subCaCertificate.Signature);
            Assert.Equal(
                "61ea45712f8de13f0a9b9548f1f23ca25816ca96c4ffdae2ab97711091b32fa48b810ff2a4fb35f3e7904a20c59be531cb47b1681db536e9f528576ea0a7a973c2c39ef90591f6ac428dc48df4096afa538ee7e21da14a7689c4979e03ec4ab00d55938bfc78bbbbc7046507085912c60d1405690f76044e87a41fcefb43366b67a11d1bfdd583ab1db470d0e22fd4f3bb324e6c8cda5f2f5ce1886437755abe9da9e7b616d09f86f01c58c6ef87f27ab0138732ad159f91bc4e9ea2530b11958d73ecb69028096794e8a26558617bed60bf32411c2d2df87af6d981f06a82832e1481d05fe01a4ce2350fa9cb58459dee0c10ebafccec49a639f4fb04486c19",
                signatureHex);

            string subjectCNHex = HexUtil.ConvertByteArrayToHexString(subCaCertificate.Subject.CommonName);
            Assert.Equal(
                "53796d616e7465632042617369632044562053534c204341202d204731",
                subjectCNHex);

            string issuerCNHex = HexUtil.ConvertByteArrayToHexString(subCaCertificate.Issuer.CommonName);
            Assert.Equal(
                "566572695369676e20436c6173732033205075626c6963205072696d6172792043657274696669636174696f6e20417574686f72697479202d204735",
                issuerCNHex);

            Assert.True(subCaCertificate.DNsNames.Length == 0);
        }

        [Fact]
        public void Should_Parse_ONT_IO_End_User_SSL_Certificate()
        {
            string sSLCertFilePath = "../../../test-data/certs/www.ont.io/ont.io.cer";
            byte[] sSlCertEncoded = File.ReadAllBytes(sSLCertFilePath);
            Certificate sslCertificate = CertificateParser.Parse(sSlCertEncoded);

            String sslCertEncodedDigestHex =
                HexUtil.ConvertByteArrayToHexString(DigestUtilities.CalculateDigest("SHA_256", sSlCertEncoded));
            Assert.Equal("b8194eb004a9efe52d1369facf6b0d4b21beea61087383ce61a4a16628780956", sslCertEncodedDigestHex);

            var sSlCertEncodedHex = HexUtil.ConvertByteArrayToHexString(sSlCertEncoded);
            Assert.Equal(
                "308205733082045ba0030201020210773088c5353d7953172721226a256d91300d06092a864886f70d01010b0500308194310b3009060355040613025553311d301b060355040a131453796d616e74656320436f72706f726174696f6e311f301d060355040b131653796d616e746563205472757374204e6574776f726b311d301b060355040b1314446f6d61696e2056616c6964617465642053534c312630240603550403131d53796d616e7465632042617369632044562053534c204341202d204731301e170d3137313132303030303030305a170d3138313031333233353935395a3011310f300d06035504030c066f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100bed44f6d1772f9056ab06d7a7b108b1b65c293fa4af695e6400864866b4b5dac96197ec74a2a7d416690c9b5031f7ea667e3449f550dbdcb747fdaf01535762e41e9f0553b57c16efc7c48ec21c698833a6bd7826421890da27362fc2a65553b052561a100396dfdbb75bacea23009b3382e7ce487367bfc2040189336d4eae2692b32a217aa5e039d8adfb66654e364b5f19ba8d062835d3a7db9ff4ddedea389c571fd69971b9169fc59242c4347279c7a31879a38545aa33c31fca3b4213f03a13a04d2426025cd9867980fa94a42b80252f9929c8aa39052a00d5358ce8c55cd65bbbc010657be9c94383fffa81d58839f4f80e8e73c7b92ae47b956b9770203010001a38202413082023d301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30090603551d130402300030610603551d20045a30583056060667810c010201304c302306082b06010505070201161768747470733a2f2f642e73796d63622e636f6d2f637073302506082b0601050507020230190c1768747470733a2f2f642e73796d63622e636f6d2f727061301f0603551d230418301680145c619eb07641a96aaa430be1c76e30296eb1cd36300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302305706082b06010505070101044b3049301f06082b060105050730018613687474703a2f2f68632e73796d63642e636f6d302606082b06010505073002861a687474703a2f2f68632e73796d63622e636f6d2f68632e63727430820103060a2b06010401d6790204020481f40481f100ef007600ddeb1d2b7a0d4fa6208b81ad8168707e2e8e9d01d55c888d3d11c4cdb6ecbecc0000015fd7dfbb25000004030047304502207521b4fb9b668e7b1e9ff38d484f98ba061a0d48778fa5b01b68455dd032937a022100fef3632f1152c1c3d4ec3460637c7af29e159ea838f7e85f769215519e95792e007500a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc100000015fd7dfbb5f00000403004630440220375e45f4beffdd85dbad4f69f76ef1ed32453a9d48c3db8dba1717d3f01623cf02203ab8ed10e707fa2895b3ae4c4b591ece53df0bb444abff8e78236246cd88043b300d06092a864886f70d01010b050003820101005beb17029867c11bbfab8723ba010a22680b148668462ba80084d09b199a265477f49d753b19dbb29cc6bc0f59daad9c46dc7de5d86c775b45512ec71508e14715c701d3b39a55e1afe072feeb131426f0f84ac275607378b45364a68f3c008ba02aaf239438ca294797dcf152a01984aebff42591d1bac639d665bfee395621c48dd45a669b2f10fb0b92377441a7898adc9bc854e17e30c2b928e274eada3b5e4a6db9c903eb8a0aea0e7e7ce84fb81f0f2f74ec9f59d18497f831637acfd5c576e952583e6a5b21516a07562601d69f8f490a26e1a8a26a1a6ef4c552634b9f81d79c13af8355679443db34fee959733ef9bef71b6afead064ae6f3c030e8",
                sSlCertEncodedHex);

            Assert.Equal(3, sslCertificate.Version);
            Assert.Equal("773088c5353d7953172721226a256d91",
                HexUtil.ConvertByteArrayToHexString(sslCertificate.SerialNumber.ToByteArray()));
            Assert.Equal(true, sslCertificate.BasicConstraints.HasBasicConstraints);
            Assert.Equal(false, sslCertificate.BasicConstraints.IsCa);
            Assert.Equal(false, sslCertificate.BasicConstraints.HasPathLengthConstraint);
            Assert.Equal(0, sslCertificate.BasicConstraints.MaxPathLen);
            string subjectPublicKeyInfoHex = HexUtil.ConvertByteArrayToHexString(sslCertificate.SubjectPublicKeyInfo);
            Assert.Equal(
                "30820122300d06092a864886f70d01010105000382010f003082010a0282010100bed44f6d1772f9056ab06d7a7b108b1b65c293fa4af695e6400864866b4b5dac96197ec74a2a7d416690c9b5031f7ea667e3449f550dbdcb747fdaf01535762e41e9f0553b57c16efc7c48ec21c698833a6bd7826421890da27362fc2a65553b052561a100396dfdbb75bacea23009b3382e7ce487367bfc2040189336d4eae2692b32a217aa5e039d8adfb66654e364b5f19ba8d062835d3a7db9ff4ddedea389c571fd69971b9169fc59242c4347279c7a31879a38545aa33c31fca3b4213f03a13a04d2426025cd9867980fa94a42b80252f9929c8aa39052a00d5358ce8c55cd65bbbc010657be9c94383fffa81d58839f4f80e8e73c7b92ae47b956b9770203010001",
                subjectPublicKeyInfoHex);
            Assert.Equal("300d06092a864886f70d01010b0500",
                HexUtil.ConvertByteArrayToHexString(sslCertificate.SignatureAlgorithm));
            Assert.Equal("5253412f2f504b43533150414444494e47",
                HexUtil.ConvertByteArrayToHexString(sslCertificate.PublicKeyAlgName));

            Assert.True(sslCertificate.KeyUsage.HasKeyUsageExtension);
            Assert.True(sslCertificate.KeyUsage.IsCritical);
            Assert.True((sslCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyCertSign) == 0);
            Assert.True((sslCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.CrlSign) == 0);
            Assert.True((sslCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.None) == 0);
            Assert.True((sslCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.EncipherOnly) == 0);
            Assert.True((sslCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyAgreement) == 0);
            Assert.True((sslCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.DataEncipherment) == 0);
            Assert.True((sslCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyEncipherment) != 0);
            Assert.True((sslCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.DigitalSignature) != 0);
            Assert.True((sslCertificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.DecipherOnly) == 0);

            Assert.False(sslCertificate.SubjectKeyIdentifier.HasSubjectKeyIdentifierExtension);

            Assert.True(sslCertificate.AuthorityKeyIdentifier.HasAuthorityKeyIdentifier);
            Assert.False(sslCertificate.SubjectKeyIdentifier.IsCritical);
            Assert.Equal(HexUtil.HexStringToByteArray("5C619EB07641A96AAA430BE1C76E30296EB1CD36"),
                sslCertificate.AuthorityKeyIdentifier.keyIdentifier);

            Assert.Equal(1511136000, sslCertificate.Validity.NotBefore);
            Assert.Equal(1539475199, sslCertificate.Validity.NotAfter);

            Assert.True(sslCertificate.ExtendedKeyUsage.HasExtendedKeyUsageExtension);
            Assert.Equal(OIDS.OID_EXTENDED_KEY_USAGE_SERVER_AUTHENTICATION,
                StringUtil.ByteArrayToString(sslCertificate.ExtendedKeyUsage.Oids[0]));
            Assert.Equal(OIDS.OID_EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION,
                StringUtil.ByteArrayToString(sslCertificate.ExtendedKeyUsage.Oids[1]));
            Assert.Equal("312e332e362e312e352e352e372e332e31",
                HexUtil.ConvertByteArrayToHexString(sslCertificate.ExtendedKeyUsage.Oids[0]));
            Assert.Equal("312e332e362e312e352e352e372e332e32",
                HexUtil.ConvertByteArrayToHexString(sslCertificate.ExtendedKeyUsage.Oids[1]));

            Assert.Equal("ont.io", StringUtil.ByteArrayToString(sslCertificate.Subject.CommonName));
            Assert.Equal("6f6e742e696f", HexUtil.ConvertByteArrayToHexString(sslCertificate.Subject.CommonName));
            Assert.Equal("ont.io", StringUtil.ByteArrayToString(sslCertificate.DNsNames[0]));
            Assert.Equal("6f6e742e696f", HexUtil.ConvertByteArrayToHexString(sslCertificate.DNsNames[0]));
            Assert.Equal("www.ont.io", StringUtil.ByteArrayToString(sslCertificate.DNsNames[1]));
            Assert.Equal("7777772e6f6e742e696f", HexUtil.ConvertByteArrayToHexString(sslCertificate.DNsNames[1]));

            string TbsCertificateHex = HexUtil.ConvertByteArrayToHexString(sslCertificate.TbsCertificate);
            Assert.Equal(
                "3082045ba0030201020210773088c5353d7953172721226a256d91300d06092a864886f70d01010b0500308194310b3009060355040613025553311d301b060355040a131453796d616e74656320436f72706f726174696f6e311f301d060355040b131653796d616e746563205472757374204e6574776f726b311d301b060355040b1314446f6d61696e2056616c6964617465642053534c312630240603550403131d53796d616e7465632042617369632044562053534c204341202d204731301e170d3137313132303030303030305a170d3138313031333233353935395a3011310f300d06035504030c066f6e742e696f30820122300d06092a864886f70d01010105000382010f003082010a0282010100bed44f6d1772f9056ab06d7a7b108b1b65c293fa4af695e6400864866b4b5dac96197ec74a2a7d416690c9b5031f7ea667e3449f550dbdcb747fdaf01535762e41e9f0553b57c16efc7c48ec21c698833a6bd7826421890da27362fc2a65553b052561a100396dfdbb75bacea23009b3382e7ce487367bfc2040189336d4eae2692b32a217aa5e039d8adfb66654e364b5f19ba8d062835d3a7db9ff4ddedea389c571fd69971b9169fc59242c4347279c7a31879a38545aa33c31fca3b4213f03a13a04d2426025cd9867980fa94a42b80252f9929c8aa39052a00d5358ce8c55cd65bbbc010657be9c94383fffa81d58839f4f80e8e73c7b92ae47b956b9770203010001a38202413082023d301d0603551d110416301482066f6e742e696f820a7777772e6f6e742e696f30090603551d130402300030610603551d20045a30583056060667810c010201304c302306082b06010505070201161768747470733a2f2f642e73796d63622e636f6d2f637073302506082b0601050507020230190c1768747470733a2f2f642e73796d63622e636f6d2f727061301f0603551d230418301680145c619eb07641a96aaa430be1c76e30296eb1cd36300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302305706082b06010505070101044b3049301f06082b060105050730018613687474703a2f2f68632e73796d63642e636f6d302606082b06010505073002861a687474703a2f2f68632e73796d63622e636f6d2f68632e63727430820103060a2b06010401d6790204020481f40481f100ef007600ddeb1d2b7a0d4fa6208b81ad8168707e2e8e9d01d55c888d3d11c4cdb6ecbecc0000015fd7dfbb25000004030047304502207521b4fb9b668e7b1e9ff38d484f98ba061a0d48778fa5b01b68455dd032937a022100fef3632f1152c1c3d4ec3460637c7af29e159ea838f7e85f769215519e95792e007500a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc100000015fd7dfbb5f00000403004630440220375e45f4beffdd85dbad4f69f76ef1ed32453a9d48c3db8dba1717d3f01623cf02203ab8ed10e707fa2895b3ae4c4b591ece53df0bb444abff8e78236246cd88043b",
                TbsCertificateHex);

            string tBSSignatureAlgorithmHex = HexUtil.ConvertByteArrayToHexString(sslCertificate.TBSSignatureAlgorithm);
            Assert.Equal(
                "300d06092a864886f70d01010b0500",
                tBSSignatureAlgorithmHex);

            var signatureHex = HexUtil.ConvertByteArrayToHexString(sslCertificate.Signature);
            Assert.Equal(
                "5beb17029867c11bbfab8723ba010a22680b148668462ba80084d09b199a265477f49d753b19dbb29cc6bc0f59daad9c46dc7de5d86c775b45512ec71508e14715c701d3b39a55e1afe072feeb131426f0f84ac275607378b45364a68f3c008ba02aaf239438ca294797dcf152a01984aebff42591d1bac639d665bfee395621c48dd45a669b2f10fb0b92377441a7898adc9bc854e17e30c2b928e274eada3b5e4a6db9c903eb8a0aea0e7e7ce84fb81f0f2f74ec9f59d18497f831637acfd5c576e952583e6a5b21516a07562601d69f8f490a26e1a8a26a1a6ef4c552634b9f81d79c13af8355679443db34fee959733ef9bef71b6afead064ae6f3c030e8",
                signatureHex);

            string subjectCNHex = HexUtil.ConvertByteArrayToHexString(sslCertificate.Subject.CommonName);
            Assert.Equal(
                "6f6e742e696f",
                subjectCNHex);

            string issuerCNHex = HexUtil.ConvertByteArrayToHexString(sslCertificate.Issuer.CommonName);
            Assert.Equal(
                "53796d616e7465632042617369632044562053534c204341202d204731",
                issuerCNHex);
        }
    }
}