using System.IO;
using System.Linq;
using System.Text;
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract;
using io.certledger.smartcontract.platform.netcore;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace CertLedgerTestProject
{
    public class SignUtil
    {
        private static readonly byte[] OPERATION_ADD_TRUSTED_ROOT_CA_CERTIFICATE =
            HexUtil.HexStringToByteArray("4144445f545255535445445f524f4f545f43415f4345525449464943415445");

        private static readonly byte[] OPERATION_UNTRUST_ROOT_CA_CERTIFICATE =
            HexUtil.HexStringToByteArray("554e54525553545f524f4f545f43415f4345525449464943415445");

        static readonly byte[] ROOT_CA_REQUEST_SIGNATURE_PKCS8_PRIVATE_KEY =
            HexUtil.HexStringToByteArray(
                "3081bf020100301006072a8648ce3d020106052b810400220481a73081a40201010430ae7ef2d88b44b331785c77dfd2e05c7999b09459d6f970c9a42ba9bc44caa3c2e6045df3e23ca611befce2bb64dfbf3aa00706052b81040022a164036200042dfe424daf556803bf03df26a46f8b28d6eb84efb397334253b8986ac9591adbbe8b64fc23f15d2be0578ba1fa05bfbb7fa463f5a201e69d108f2e932243d7d8190de0d7caf4d2df16bf32c9e056c5ce83be39ba91675b3af09e8c164bed3571");

        private static readonly byte[] OPERATION_REVOKE_SSL_CERTIFICATE =
            HexUtil.HexStringToByteArray("5245564f4b455f53534c5f4345525449464943415445");

        public static byte[] generateAddTrustedRootCAOperationRequestSignature(byte[] rootCertBytes)
        {
            ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            byte[] dataForSign = ArrayUtil.Concat(OPERATION_ADD_TRUSTED_ROOT_CA_CERTIFICATE, rootCertBytes);
            signer.Init(true, decodePrivateKeyParameter(ROOT_CA_REQUEST_SIGNATURE_PKCS8_PRIVATE_KEY));
            signer.BlockUpdate(dataForSign, 0, dataForSign.Length);
            return signer.GenerateSignature();
        }

        public static byte[] generateUntrustRootCAOperationRequestSignature(byte[] rootCertBytes)
        {
            ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            byte[] dataForSign = ArrayUtil.Concat(OPERATION_UNTRUST_ROOT_CA_CERTIFICATE, rootCertBytes);
            signer.Init(true, decodePrivateKeyParameter(ROOT_CA_REQUEST_SIGNATURE_PKCS8_PRIVATE_KEY));
            signer.BlockUpdate(dataForSign, 0, dataForSign.Length);
            return signer.GenerateSignature();
        }

        public static byte[] generateRevokeSSLCertificateOperationRequestECDSASignature(byte[] encodedCertificateBytes,
            string pkcs8FilePath)
        {
            string signAlg = "SHA-256withECDSA";
            return generateRevokeSSLCertificateOperationRequestSignature(signAlg, encodedCertificateBytes,
                pkcs8FilePath);
        }

        public static byte[] generateRevokeSSLCertificateOperationRequestRSAPSSSignature(byte[] encodedCertificateBytes,
            string pkcs8FilePath)
        {
            string signAlg = "SHA256withRSA/PSS";
            return generateRevokeSSLCertificateOperationRequestSignature(signAlg, encodedCertificateBytes,
                pkcs8FilePath);
        }

        public static byte[] generateRevokeSSLCertificateOperationRequestSignature(string signAlg,
            byte[] encodedCertificateBytes, string pkcs8FilePath)
        {
            ISigner signer = SignerUtilities.GetSigner(signAlg);
            byte[] dataForSign = ArrayUtil.Concat(OPERATION_REVOKE_SSL_CERTIFICATE, encodedCertificateBytes);
            signer.Init(true, readPrivateKeyFromP8File(pkcs8FilePath));
            signer.BlockUpdate(dataForSign, 0, dataForSign.Length);
            return signer.GenerateSignature();
        }

        public static AsymmetricKeyParameter readPrivateKeyFromP8File(string pkcs8FilePath)
        {    
            var fileStream = File.OpenText (pkcs8FilePath);
            var pemReader = new PemReader (fileStream);
            var KeyParameter = (AsymmetricKeyParameter)pemReader.ReadObject ();
            return KeyParameter;
        }

        private static AsymmetricKeyParameter decodePrivateKeyParameter(byte[] encodedPkcs8Data)
        {
            return PrivateKeyFactory.CreateKey(encodedPkcs8Data);
        }
    }
}