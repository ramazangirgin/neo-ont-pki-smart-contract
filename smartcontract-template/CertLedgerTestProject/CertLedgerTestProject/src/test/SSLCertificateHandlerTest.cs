using System.IO;
using CertLedgerBusinessSCTemplate.src.io.certledger;
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract;
using io.certledger.smartcontract.platform.netcore;
using Org.BouncyCastle.Security;
using Xunit;

namespace CertLedgerTestProject
{
    public class SSLCertificateHandlerTest
    {
        public SSLCertificateHandlerTest()
        {
            StorageUtil.clearStorage();
        }

        [Fact]
        public void Should_Add_SSL_Certificate()
        {
            {
                string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
                byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
                byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
                byte[] requestSignature = SignUtil.generateAddTrustedRootCAOperationRequestSignature(rootCertEncoded);
                bool result =
                    RootCaCertificateHandler.AddTrustedRootCaCertificate(rootCertDigest, rootCertEncoded,
                        requestSignature);
                Assert.True(result);
            }

            {
                string subCaCertFilePath = "../../../test-data/certs/test-ca/Test-Sub-CA-RSA-2048.cer";
                byte[] subCaCertEncoded = File.ReadAllBytes(subCaCertFilePath);
                byte[] subCaCertificateHash = DigestUtilities.CalculateDigest("SHA_256", subCaCertEncoded);
                byte[] subCaAddRequestSignature = null;
                bool result = SubCaCertificateHandler.AddSubCaCertificate(subCaCertificateHash, subCaCertEncoded,
                    subCaAddRequestSignature);
                Assert.True(result);
            }

            string sSLCertFilePath = "../../../test-data/certs/test-ca/Test-SSL-RSA-2048.cer";
            byte[] sSLCertEncoded = File.ReadAllBytes(sSLCertFilePath);
            byte[] sSLCertHash = DigestUtilities.CalculateDigest("SHA_256", sSLCertEncoded);
            bool sslCertAddResult = SslCertificateHandler.AddSslCertificate(sSLCertHash, sSLCertEncoded);
            Assert.True(sslCertAddResult);
            Certificate sslCertificate = CertificateParser.Parse(sSLCertEncoded);

            byte[] sSLCertificateEntryByte = StorageUtil.readFromStorage(sSLCertHash);
            EndEntityCertificateEntry sSLCertificateEntry =
                (EndEntityCertificateEntry) SerializationUtil.Deserialize(sSLCertificateEntryByte);
            Assert.False(sSLCertificateEntry.IsRevoked);
            Assert.Equal(sSLCertificateEntry.CertificateValue, sSLCertEncoded);

            //Is Added To Issuer list
            {
                byte[] storageKey = ArrayUtil.Concat(CertificateStorageManager.ELEMENT_LIST,
                    sslCertificate.AuthorityKeyIdentifier.keyIdentifier);
                byte[] certHashMapEntrySerialized = StorageUtil.readFromStorage(storageKey);
                Assert.True(certHashMapEntrySerialized != null);
                CertificateHashMapEntry certHashMapEntry =
                    (CertificateHashMapEntry) SerializationUtil.Deserialize(certHashMapEntrySerialized);
                Assert.True(certHashMapEntry.certificateHashArray != null);
                Assert.True(certHashMapEntry.certificateHashArray.Length == 1);
                byte[] subjectKeyIdCertificateHashEntrySerialized = certHashMapEntry.certificateHashArray[0];
                CertificateHashEntry subjectKeyIdCertificateHashEntry =
                    (CertificateHashEntry) SerializationUtil.Deserialize(subjectKeyIdCertificateHashEntrySerialized);
                Assert.Equal(subjectKeyIdCertificateHashEntry.CertificateHash, sSLCertHash);
                Assert.False(subjectKeyIdCertificateHashEntry.IsCa);
            }
            //Domain Name List - Common Name
            {
                byte[] certHashMapEntrySerialized =
                    StorageUtil.readFromStorage(HexUtil.HexStringToByteArray("6f6e742e696f"));
                Assert.True(certHashMapEntrySerialized != null);
                CertificateHashMapEntry certHashMapEntry =
                    (CertificateHashMapEntry) SerializationUtil.Deserialize(certHashMapEntrySerialized);
                Assert.True(certHashMapEntry.certificateHashArray != null);
                Assert.True(certHashMapEntry.certificateHashArray.Length == 1);
                byte[] subjectKeyIdCertificateHashEntrySerialized = certHashMapEntry.certificateHashArray[0];
                CertificateHashEntry subjectKeyIdCertificateHashEntry =
                    (CertificateHashEntry) SerializationUtil.Deserialize(subjectKeyIdCertificateHashEntrySerialized);
                Assert.Equal(subjectKeyIdCertificateHashEntry.CertificateHash, sSLCertHash);
                Assert.False(subjectKeyIdCertificateHashEntry.IsCa);
            }
            //Domain Name List - Subject Alternative Name 
            {
                byte[] certHashMapEntrySerialized =
                    StorageUtil.readFromStorage(HexUtil.HexStringToByteArray("7777772e6f6e742e696f"));
                Assert.True(certHashMapEntrySerialized != null);
                CertificateHashMapEntry certHashMapEntry =
                    (CertificateHashMapEntry) SerializationUtil.Deserialize(certHashMapEntrySerialized);
                Assert.True(certHashMapEntry.certificateHashArray != null);
                Assert.True(certHashMapEntry.certificateHashArray.Length == 1);
                byte[] subjectKeyIdCertificateHashEntrySerialized = certHashMapEntry.certificateHashArray[0];
                CertificateHashEntry subjectKeyIdCertificateHashEntry =
                    (CertificateHashEntry) SerializationUtil.Deserialize(subjectKeyIdCertificateHashEntrySerialized);
                Assert.Equal(subjectKeyIdCertificateHashEntry.CertificateHash, sSLCertHash);
                Assert.False(subjectKeyIdCertificateHashEntry.IsCa);
            }
        }

        [Fact]
        public void Should_Revoke_SSL_Certificate_When_Request_Signed_With_SSL_RSA_Private_Key()
        {
            {
                string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
                byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
                byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
                byte[] requestSignature = SignUtil.generateAddTrustedRootCAOperationRequestSignature(rootCertEncoded);
                bool result =
                    RootCaCertificateHandler.AddTrustedRootCaCertificate(rootCertDigest, rootCertEncoded,
                        requestSignature);
                Assert.True(result);
            }

            {
                string subCaCertFilePath = "../../../test-data/certs/test-ca/Test-Sub-CA-RSA-2048.cer";
                byte[] subCaCertEncoded = File.ReadAllBytes(subCaCertFilePath);
                byte[] subCaCertificateHash = DigestUtilities.CalculateDigest("SHA_256", subCaCertEncoded);
                byte[] subCaAddRequestSignature = null;
                bool result = SubCaCertificateHandler.AddSubCaCertificate(subCaCertificateHash, subCaCertEncoded,
                    subCaAddRequestSignature);
                Assert.True(result);
            }

            string sSLCertFilePath = "../../../test-data/certs/test-ca/Test-SSL-RSA-2048.cer";
            byte[] sSLCertEncoded = File.ReadAllBytes(sSLCertFilePath);
            byte[] sSLCertHash = DigestUtilities.CalculateDigest("SHA_256", sSLCertEncoded);
            bool sslCertAddResult = SslCertificateHandler.AddSslCertificate(sSLCertHash, sSLCertEncoded);
            Assert.True(sslCertAddResult);

            string sSLCertPkcs8PrivateKeyFilePath = "../../../test-data/certs/test-ca/Test-SSL-RSA-2048.pk8";
            byte[] revokeSSLCertificateRequestSignature =
                SignUtil.generateRevokeSSLCertificateOperationRequestRSAPSSSignature(sSLCertEncoded,
                    sSLCertPkcs8PrivateKeyFilePath);

            Certificate sslCertificate = CertificateParser.Parse(sSLCertEncoded);
            bool revokeSSLCertificateResult = SslCertificateHandler.RevokeSslCertificate(sSLCertHash, sSLCertEncoded,
                revokeSSLCertificateRequestSignature);
            Assert.True(revokeSSLCertificateResult);

            byte[] sSLCertificateEntryByte = StorageUtil.readFromStorage(sSLCertHash);
            EndEntityCertificateEntry sSLCertificateEntry =
                (EndEntityCertificateEntry) SerializationUtil.Deserialize(sSLCertificateEntryByte);
            Assert.True(sSLCertificateEntry.IsRevoked);
            Assert.Equal(sSLCertificateEntry.CertificateValue, sSLCertEncoded);
        }
        
        [Fact]
        public void Should_Revoke_SSL_Certificate_When_Request_Signed_With_SSL_EC_Private_Key()
        {
            {
                string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
                byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
                byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
                byte[] requestSignature = SignUtil.generateAddTrustedRootCAOperationRequestSignature(rootCertEncoded);
                bool result =
                    RootCaCertificateHandler.AddTrustedRootCaCertificate(rootCertDigest, rootCertEncoded,
                        requestSignature);
                Assert.True(result);
            }

            {
                string subCaCertFilePath = "../../../test-data/certs/test-ca/Test-Sub-CA-RSA-2048.cer";
                byte[] subCaCertEncoded = File.ReadAllBytes(subCaCertFilePath);
                byte[] subCaCertificateHash = DigestUtilities.CalculateDigest("SHA_256", subCaCertEncoded);
                byte[] subCaAddRequestSignature = null;
                bool result = SubCaCertificateHandler.AddSubCaCertificate(subCaCertificateHash, subCaCertEncoded,
                    subCaAddRequestSignature);
                Assert.True(result);
            }

            string sSLCertFilePath = "../../../test-data/certs/test-ca/Test-SSL-EC-P256.cer";
            byte[] sSLCertEncoded = File.ReadAllBytes(sSLCertFilePath);
            byte[] sSLCertHash = DigestUtilities.CalculateDigest("SHA_256", sSLCertEncoded);
            bool sslCertAddResult = SslCertificateHandler.AddSslCertificate(sSLCertHash, sSLCertEncoded);
            Assert.True(sslCertAddResult);

            string sSLCertPkcs8PrivateKeyFilePath = "../../../test-data/certs/test-ca/Test-SSL-EC-P256.pk8";
            byte[] revokeSSLCertificateRequestSignature =
                SignUtil.generateRevokeSSLCertificateOperationRequestECDSASignature(sSLCertEncoded,
                    sSLCertPkcs8PrivateKeyFilePath);

            Certificate sslCertificate = CertificateParser.Parse(sSLCertEncoded);
            bool revokeSSLCertificateResult = SslCertificateHandler.RevokeSslCertificate(sSLCertHash, sSLCertEncoded,
                revokeSSLCertificateRequestSignature);
            Assert.True(revokeSSLCertificateResult);

            byte[] sSLCertificateEntryByte = StorageUtil.readFromStorage(sSLCertHash);
            EndEntityCertificateEntry sSLCertificateEntry =
                (EndEntityCertificateEntry) SerializationUtil.Deserialize(sSLCertificateEntryByte);
            Assert.True(sSLCertificateEntry.IsRevoked);
            Assert.Equal(sSLCertificateEntry.CertificateValue, sSLCertEncoded);
        }

        [Fact]
        public void Should_Revoke_SSL_Certificate_When_Request_Signed_With_Issuer_Private_Key()
        {
            {
                string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
                byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
                byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
                byte[] requestSignature = SignUtil.generateAddTrustedRootCAOperationRequestSignature(rootCertEncoded);
                bool result =
                    RootCaCertificateHandler.AddTrustedRootCaCertificate(rootCertDigest, rootCertEncoded,
                        requestSignature);
                Assert.True(result);
            }

            {
                string subCaCertFilePath = "../../../test-data/certs/test-ca/Test-Sub-CA-RSA-2048.cer";
                byte[] subCaCertEncoded = File.ReadAllBytes(subCaCertFilePath);
                byte[] subCaCertificateHash = DigestUtilities.CalculateDigest("SHA_256", subCaCertEncoded);
                byte[] subCaAddRequestSignature = null;
                bool result = SubCaCertificateHandler.AddSubCaCertificate(subCaCertificateHash, subCaCertEncoded,
                    subCaAddRequestSignature);
                Assert.True(result);
            }

            string sSLCertFilePath = "../../../test-data/certs/test-ca/Test-SSL-RSA-2048.cer";
            byte[] sSLCertEncoded = File.ReadAllBytes(sSLCertFilePath);
            byte[] sSLCertHash = DigestUtilities.CalculateDigest("SHA_256", sSLCertEncoded);
            bool sslCertAddResult = SslCertificateHandler.AddSslCertificate(sSLCertHash, sSLCertEncoded);
            Assert.True(sslCertAddResult);

            string sSLCertIssuerPkcs8PrivateKeyFilePath = "../../../test-data/certs/test-ca/Test-Sub-CA-RSA-2048.pk8";
            byte[] revokeSSLCertificateRequestSignature =
                SignUtil.generateRevokeSSLCertificateOperationRequestRSAPSSSignature(sSLCertEncoded,
                    sSLCertIssuerPkcs8PrivateKeyFilePath);

            Certificate sslCertificate = CertificateParser.Parse(sSLCertEncoded);
            bool revokeSSLCertificateResult = SslCertificateHandler.RevokeSslCertificate(sSLCertHash, sSLCertEncoded,
                revokeSSLCertificateRequestSignature);
            Assert.True(revokeSSLCertificateResult);

            byte[] sSLCertificateEntryByte = StorageUtil.readFromStorage(sSLCertHash);
            EndEntityCertificateEntry sSLCertificateEntry =
                (EndEntityCertificateEntry) SerializationUtil.Deserialize(sSLCertificateEntryByte);
            Assert.True(sSLCertificateEntry.IsRevoked);
            Assert.Equal(sSLCertificateEntry.CertificateValue, sSLCertEncoded);
        }

        [Fact]
        public void Should_Not_Revoke_SSL_Certificate_When_Request_Signature_Is_Invalid()
        {
            {
                string rootCertFilePath = "../../../test-data/certs/test-ca/Test-Root-CA-RSA-2048.cer";
                byte[] rootCertEncoded = File.ReadAllBytes(rootCertFilePath);
                byte[] rootCertDigest = DigestUtilities.CalculateDigest("SHA_256", rootCertEncoded);
                byte[] requestSignature = SignUtil.generateAddTrustedRootCAOperationRequestSignature(rootCertEncoded);
                bool result =
                    RootCaCertificateHandler.AddTrustedRootCaCertificate(rootCertDigest, rootCertEncoded,
                        requestSignature);
                Assert.True(result);
            }

            {
                string subCaCertFilePath = "../../../test-data/certs/test-ca/Test-Sub-CA-RSA-2048.cer";
                byte[] subCaCertEncoded = File.ReadAllBytes(subCaCertFilePath);
                byte[] subCaCertificateHash = DigestUtilities.CalculateDigest("SHA_256", subCaCertEncoded);
                byte[] subCaAddRequestSignature = null;
                bool result = SubCaCertificateHandler.AddSubCaCertificate(subCaCertificateHash, subCaCertEncoded,
                    subCaAddRequestSignature);
                Assert.True(result);
            }

            string sSLCertFilePath = "../../../test-data/certs/test-ca/Test-SSL-RSA-2048.cer";
            byte[] sSLCertEncoded = File.ReadAllBytes(sSLCertFilePath);
            byte[] sSLCertHash = DigestUtilities.CalculateDigest("SHA_256", sSLCertEncoded);
            bool sslCertAddResult = SslCertificateHandler.AddSslCertificate(sSLCertHash, sSLCertEncoded);
            Assert.True(sslCertAddResult);

            byte[] revokeSSLCertificateRequestSignature = StringUtil.StringToByteArray("InvalidSignature");

            Certificate sslCertificate = CertificateParser.Parse(sSLCertEncoded);
            bool revokeSSLCertificateResult = SslCertificateHandler.RevokeSslCertificate(sSLCertHash, sSLCertEncoded,
                revokeSSLCertificateRequestSignature);
            Assert.False(revokeSSLCertificateResult);

            byte[] sSLCertificateEntryByte = StorageUtil.readFromStorage(sSLCertHash);
            EndEntityCertificateEntry sSLCertificateEntry =
                (EndEntityCertificateEntry) SerializationUtil.Deserialize(sSLCertificateEntryByte);
            Assert.False(sSLCertificateEntry.IsRevoked);
            Assert.Equal(sSLCertificateEntry.CertificateValue, sSLCertEncoded);
        }
    }
}