namespace io.certledger.smartcontract.business
{
    class CertificateSignatureValidator
    {
        public static bool ValidateSelfSignedCertificateSignature(Certificate certificate)
        {
            return Validate(certificate.TbsCertificate, certificate.SubjectPublicKeyInfo, certificate.SignatureAlgorithm, certificate.Signature);
        }

        public static bool ValidateCertificateSignature(Certificate certificate, Certificate issuerCertificate)
        {
            return Validate(certificate.TbsCertificate, issuerCertificate.SubjectPublicKeyInfo, certificate.SignatureAlgorithm, certificate.Signature);
        }

        static bool Validate(byte[] tbsCertificate, byte[] subjectPublicKeyInfo, byte[] signatureAlgorithm, byte[] signatureValue)
        {
            SignedData signedData = new SignedData();
            signedData.subjectPublicKeyInfo = subjectPublicKeyInfo;
            signedData.signedData = tbsCertificate;
            signedData.signatureAlgorithm = signatureAlgorithm;
            signedData.signatureValue = signatureValue;
            return SignatureValidator.Validate(signedData);
            //todo: Signature will be validated using parameter fields
            //now always return signature is valid
            //todo: add real implementation code
            return true;
        }
    }
}