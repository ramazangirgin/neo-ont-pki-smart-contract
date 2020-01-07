#if NEO
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo;
#endif
#if NET_CORE
using io.certledger.smartcontract.platform.netcore;
#endif
namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class CertificateSignatureValidator
    {
        public static bool ValidateSelfSignedCertificateSignature(Certificate certificate)
        {
            return ValidateCertificateSignature(certificate,certificate);
        }

        public static bool ValidateCertificateSignature(Certificate certificate, Certificate issuerCertificate)
        {
#if NEO
            return NeoVMSignatureValidator.CheckCertificateSignature(certificate.EncodedValue,issuerCertificate.EncodedValue);
#endif
#if NET_CORE
            SignedData signedData = new SignedData();
            signedData.subjectPublicKeyInfo = issuerCertificate.SubjectPublicKeyInfo;
            signedData.signedData = certificate.TbsCertificate;
            signedData.signatureAlgorithm = certificate.SignatureAlgorithm;
            signedData.signatureValue = certificate.Signature;
            return NetCoreSignatureValidator.Validate(signedData);
#endif

        }
    }

    public class SignedData
    {
        public byte[] signedData;
        public byte[] signatureAlgorithm;
        public byte[] subjectPublicKeyInfo;
        public byte[] signatureValue;
    }
}