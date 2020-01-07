using System.IO;
using CertLedgerBusinessSCTemplate.src.io.certledger;
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract;
using io.certledger.smartcontract.platform.netcore;
using Org.BouncyCastle.Security;
using Xunit;

namespace CertLedgerTestProject
{
    public class SignatureValidatorTest
    {
    
        public SignatureValidatorTest()
        {
            StorageUtil.clearStorage();
        }

        [Fact]
        public void Should_Validate_Root_Ca_Signature()
        {
            string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
            byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
            byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
            Certificate rootCertificate = CertificateParser.Parse(rootCertEncoded);
            bool validationResult = CertificateSignatureValidator.ValidateCertificateSignature(rootCertificate, rootCertificate);
            Assert.True(validationResult);
        }

        [Fact]
        public void Should_Validate_SubCA_Signature_With_Root_Ca_Public_Key()
        {
            string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
            byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
            Certificate rootCertificate = CertificateParser.Parse(rootCertEncoded);

            string subCaCertFilePath = "../../../test-data/certs/test-ca/Test-Sub-CA-RSA-2048.cer";
            byte[] subCaCertEncoded = File.ReadAllBytes(subCaCertFilePath);
            Certificate subCaCertificate = CertificateParser.Parse(subCaCertEncoded);
            bool validationResult = CertificateSignatureValidator.ValidateCertificateSignature(subCaCertificate, rootCertificate);
            Assert.True(validationResult);
        }
    }
}