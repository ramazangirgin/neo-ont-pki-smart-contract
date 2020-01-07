using System.IO;
using System.Text;
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Security;
using Xunit;
using Certificate = CertLedgerBusinessSCTemplate.src.io.certledger.Certificate;

namespace CertLedgerTestProject
{
    public class RootCaCertHandlerTest
    {
        public RootCaCertHandlerTest()
        {
            StorageUtil.clearStorage();
        }

        [Fact]
        public void Should_Add_Trusted_Root_Certificate()
        {
            string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
            byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
            byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
            byte[] requestSignature = SignUtil.generateAddTrustedRootCAOperationRequestSignature(rootCertEncoded);
            bool result = RootCaCertificateHandler.AddTrustedRootCaCertificate(rootCertDigest, rootCertEncoded, requestSignature);
            Assert.True(result);
            Certificate rootCertificate = CertificateParser.Parse(rootCertEncoded);

            byte[] rootCACertificateEntryByte = StorageUtil.readFromStorage(rootCertDigest);
            CaCertificateEntry caCertificateEntry =
                (CaCertificateEntry) SerializationUtil.Deserialize(rootCACertificateEntryByte);
            Assert.True(caCertificateEntry.IsTrusted);
            Assert.False(caCertificateEntry.IsRevoked);
            Assert.Equal(caCertificateEntry.CertificateValue, rootCertEncoded);

            byte[] cACertificateSubjectKeyIdEntrySerialized =
                StorageUtil.readFromStorage(rootCertificate.SubjectKeyIdentifier.keyIdentifier);
            CaCertificateSubjectKeyIdEntry cACertificateSubjectKeyIdEntry =
                (CaCertificateSubjectKeyIdEntry) SerializationUtil.Deserialize(
                    cACertificateSubjectKeyIdEntrySerialized);
            Assert.True(cACertificateSubjectKeyIdEntry.IsRootCa);
            Assert.Equal(cACertificateSubjectKeyIdEntry.CertificateHash, rootCertDigest);

            byte[] certificateHashMapEntrySerialized =
                StorageUtil.readFromStorage(CertificateStorageManager.TRUSTED_ROOT_CA_LIST_STORAGE_KEY);
            CertificateHashMapEntry trustedRootCAListHashMapEntry =
                (CertificateHashMapEntry) SerializationUtil.Deserialize(certificateHashMapEntrySerialized);
            Assert.Equal(1, trustedRootCAListHashMapEntry.certificateHashArray.Length);
            byte[] certificateHashEntrySerialized = trustedRootCAListHashMapEntry.certificateHashArray[0];
            CertificateHashEntry certificateHashEntry =
                (CertificateHashEntry) SerializationUtil.Deserialize(certificateHashEntrySerialized);
            Assert.True(certificateHashEntry.IsCa);
            Assert.Equal(rootCertDigest, certificateHashEntry.CertificateHash);
        }
        
        [Fact]
        public void Should_Return_False_When_Request_Signature_Is_Invalid_In_Add_Trusted_Root_Certificate()
        {
            string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
            byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
            byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
            byte[] requestSignature = StringUtil.StringToByteArray("InvalidSignature");
            bool result = RootCaCertificateHandler.AddTrustedRootCaCertificate(rootCertDigest, rootCertEncoded, requestSignature);
            Assert.False(result);
        }

        [Fact]
        public void Should_UnTrusted_Root_Certificate()
        {
            string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
            byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
            byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
            byte[] requestSignature = SignUtil.generateAddTrustedRootCAOperationRequestSignature(rootCertEncoded);
            bool result =
                RootCaCertificateHandler.AddTrustedRootCaCertificate(rootCertDigest, rootCertEncoded, requestSignature);
            Assert.True(result);
            Certificate rootCertificate = CertificateParser.Parse(rootCertEncoded);

            byte[] rootCACertificateEntryByte = StorageUtil.readFromStorage(rootCertDigest);
            CaCertificateEntry caCertificateEntry =
                (CaCertificateEntry) SerializationUtil.Deserialize(rootCACertificateEntryByte);
            Assert.True(caCertificateEntry.IsTrusted);
            Assert.False(caCertificateEntry.IsRevoked);
            Assert.Equal(caCertificateEntry.CertificateValue, rootCertEncoded);

            byte[] cACertificateSubjectKeyIdEntrySerialized =
                StorageUtil.readFromStorage(rootCertificate.SubjectKeyIdentifier.keyIdentifier);
            CaCertificateSubjectKeyIdEntry cACertificateSubjectKeyIdEntry =
                (CaCertificateSubjectKeyIdEntry) SerializationUtil.Deserialize(
                    cACertificateSubjectKeyIdEntrySerialized);
            Assert.True(cACertificateSubjectKeyIdEntry.IsRootCa);
            Assert.Equal(cACertificateSubjectKeyIdEntry.CertificateHash, rootCertDigest);

            byte[] certificateHashMapEntrySerialized =
                StorageUtil.readFromStorage(CertificateStorageManager.TRUSTED_ROOT_CA_LIST_STORAGE_KEY);
            CertificateHashMapEntry trustedRootCAListHashMapEntry =
                (CertificateHashMapEntry) SerializationUtil.Deserialize(certificateHashMapEntrySerialized);
            Assert.Equal(1, trustedRootCAListHashMapEntry.certificateHashArray.Length);
            byte[] certificateHashEntrySerialized = trustedRootCAListHashMapEntry.certificateHashArray[0];
            CertificateHashEntry certificateHashEntry =
                (CertificateHashEntry) SerializationUtil.Deserialize(certificateHashEntrySerialized);
            Assert.True(certificateHashEntry.IsCa);
            Assert.Equal(rootCertDigest, certificateHashEntry.CertificateHash);

            string subCaCertFilePath = "../../../test-data/certs/test-ca/Test-Sub-CA-RSA-2048.cer";
            byte[] subCaCertEncoded = File.ReadAllBytes(subCaCertFilePath);
            byte[] subCaCertificateHash = DigestUtilities.CalculateDigest("SHA_256", subCaCertEncoded);
            byte[] subCaAddRequestSignature = null;
            result = SubCaCertificateHandler.AddSubCaCertificate(subCaCertificateHash, subCaCertEncoded,
                subCaAddRequestSignature);
            Assert.True(result);

            string sSLCertFilePath = "../../../test-data/certs/test-ca/Test-SSL-RSA-2048.cer";
            byte[] sSLCertEncoded = File.ReadAllBytes(sSLCertFilePath);
            byte[] sSLCertHash = DigestUtilities.CalculateDigest("SHA_256", sSLCertEncoded);
            bool sslCertAddResult = SslCertificateHandler.AddSslCertificate(sSLCertHash, sSLCertEncoded);
            Assert.True(sslCertAddResult);

            byte[] subCaCertificateEntryBytes = StorageUtil.readFromStorage(subCaCertificateHash);
            CaCertificateEntry subCaCertificateEntry =
                (CaCertificateEntry) SerializationUtil.Deserialize(subCaCertificateEntryBytes);
            Assert.False(subCaCertificateEntry.IsTrusted);
            Assert.False(subCaCertificateEntry.IsRevoked);

            byte[] endEntityCertificateEntrySerialized = StorageUtil.readFromStorage(sSLCertHash);
            EndEntityCertificateEntry endEntityCertificateEntry =
                (EndEntityCertificateEntry) SerializationUtil.Deserialize(endEntityCertificateEntrySerialized);
            Assert.False(endEntityCertificateEntry.IsRevoked);

            requestSignature = SignUtil.generateUntrustRootCAOperationRequestSignature(rootCertEncoded);
            result = RootCaCertificateHandler.UntrustRootCaCertificate(rootCertDigest, rootCertEncoded,
                requestSignature);
            Assert.True(result);

            rootCACertificateEntryByte = StorageUtil.readFromStorage(rootCertDigest);
            caCertificateEntry = (CaCertificateEntry) SerializationUtil.Deserialize(rootCACertificateEntryByte);
            Assert.False(caCertificateEntry.IsTrusted);
            Assert.False(caCertificateEntry.IsRevoked);

            subCaCertificateEntry = (CaCertificateEntry) SerializationUtil.Deserialize(rootCACertificateEntryByte);
            Assert.False(subCaCertificateEntry.IsTrusted);

            subCaCertificateEntryBytes = StorageUtil.readFromStorage(subCaCertificateHash);
            subCaCertificateEntry = (CaCertificateEntry) SerializationUtil.Deserialize(subCaCertificateEntryBytes);
            Assert.True(subCaCertificateEntry.IsRevoked);

            endEntityCertificateEntrySerialized = StorageUtil.readFromStorage(sSLCertHash);
            endEntityCertificateEntry =
                (EndEntityCertificateEntry) SerializationUtil.Deserialize(endEntityCertificateEntrySerialized);
            Assert.True(endEntityCertificateEntry.IsRevoked);
        }
        
        [Fact]
        public void Should_Return_False_When_Request_Signature_Is_Invalid_In_Untrust_Root_Certificate()
        {
            string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
            byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
            byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
            byte[] requestSignature = StringUtil.StringToByteArray("InvalidSignature");
            bool result = RootCaCertificateHandler.AddTrustedRootCaCertificate(rootCertDigest, rootCertEncoded, requestSignature);
            Assert.False(result);
        }

        [Fact]
        public void Should_UnTrusted_Root_Certificate_When_Any_SubCA_And_Ssl_Certificate_Is_Not_Exist()
        {
            string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
            byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
            byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
            byte[] requestSignature = SignUtil.generateAddTrustedRootCAOperationRequestSignature(rootCertEncoded);
            bool result =
                RootCaCertificateHandler.AddTrustedRootCaCertificate(rootCertDigest, rootCertEncoded, requestSignature);
            Assert.True(result);
            Certificate rootCertificate = CertificateParser.Parse(rootCertEncoded);

            byte[] rootCACertificateEntryByte = StorageUtil.readFromStorage(rootCertDigest);
            CaCertificateEntry caCertificateEntry =
                (CaCertificateEntry) SerializationUtil.Deserialize(rootCACertificateEntryByte);
            Assert.True(caCertificateEntry.IsTrusted);
            Assert.False(caCertificateEntry.IsRevoked);
            Assert.Equal(caCertificateEntry.CertificateValue, rootCertEncoded);

            byte[] cACertificateSubjectKeyIdEntrySerialized =
                StorageUtil.readFromStorage(rootCertificate.SubjectKeyIdentifier.keyIdentifier);
            CaCertificateSubjectKeyIdEntry cACertificateSubjectKeyIdEntry =
                (CaCertificateSubjectKeyIdEntry) SerializationUtil.Deserialize(
                    cACertificateSubjectKeyIdEntrySerialized);
            Assert.True(cACertificateSubjectKeyIdEntry.IsRootCa);
            Assert.Equal(cACertificateSubjectKeyIdEntry.CertificateHash, rootCertDigest);

            byte[] certificateHashMapEntrySerialized =
                StorageUtil.readFromStorage(CertificateStorageManager.TRUSTED_ROOT_CA_LIST_STORAGE_KEY);
            CertificateHashMapEntry trustedRootCAListHashMapEntry =
                (CertificateHashMapEntry) SerializationUtil.Deserialize(certificateHashMapEntrySerialized);
            Assert.Equal(1, trustedRootCAListHashMapEntry.certificateHashArray.Length);
            byte[] certificateHashEntrySerialized = trustedRootCAListHashMapEntry.certificateHashArray[0];
            CertificateHashEntry certificateHashEntry =
                (CertificateHashEntry) SerializationUtil.Deserialize(certificateHashEntrySerialized);
            Assert.True(certificateHashEntry.IsCa);
            Assert.Equal(rootCertDigest, certificateHashEntry.CertificateHash);

            requestSignature = SignUtil.generateUntrustRootCAOperationRequestSignature(rootCertEncoded);
            result = RootCaCertificateHandler.UntrustRootCaCertificate(rootCertDigest, rootCertEncoded,
                requestSignature);
            Assert.True(result);

            rootCACertificateEntryByte = StorageUtil.readFromStorage(rootCertDigest);
            caCertificateEntry = (CaCertificateEntry) SerializationUtil.Deserialize(rootCACertificateEntryByte);
            Assert.False(caCertificateEntry.IsTrusted);
            Assert.False(caCertificateEntry.IsRevoked);
        }
    }
}