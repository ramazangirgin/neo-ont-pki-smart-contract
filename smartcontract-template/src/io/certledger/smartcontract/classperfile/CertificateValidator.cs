using CertLedgerBusinessSCTemplate.io.certledger.smartcontract.business;

namespace io.certledger.smartcontract.business
{
    public class CertificateValidator
    {
        public static bool ValidateRootCaCertificate(Certificate rootCaCertificate)
        {
            if (!CertificateFieldValidator.Validate(rootCaCertificate))
            {
                return false;
            }

            if (!CertificateSignatureValidator.ValidateSelfSignedCertificateSignature(rootCaCertificate))
            {
                return false;
            }

            if (!CheckValidityPeriod(rootCaCertificate))
            {
                return false;
            }

            if (!ValidateRootCaCertificateFields(rootCaCertificate))
            {
                return false;
            }

            return true;
        }

        public static bool ValidateRootCaCertificateFields(Certificate certificate)
        {
            if (!certificate.BasicConstraints.HasBasicConstraints || !certificate.BasicConstraints.IsCa)
            {
                return false;
            }

            if (!ValidateCaCertificateKeyUsage(certificate.KeyUsage.KeyUsageFlags))
            {
                return false;
            }

            return true;
        }

        public static bool ValidateSubCaCertificate(Certificate subCaCertificate)
        {
            if (!CertificateFieldValidator.Validate(subCaCertificate))
            {
                return false;
            }

            if (!CheckValidityPeriod(subCaCertificate))
            {
                return false;
            }

            if (!CertificateChainValidator.ValidateCertificateSignatureWithChain(subCaCertificate))
            {
                return false;
            }

            return true;
        }

        public static bool ValidateSslCertificateFields(Certificate certificate)
        {
            if (!CertificateFieldValidator.Validate(certificate))
            {
                return false;
            }

            if (certificate.BasicConstraints.HasBasicConstraints)
            {
                if (certificate.BasicConstraints.IsCa)
                {
                    return false;
                }
            }

            if (!ValidateSslCertificateKeyUsage(certificate.KeyUsage.KeyUsageFlags))
            {
                return false;
            }

            if (!ValidateSslCertificateExtendedKeyUsage(certificate.ExtendedKeyUsage.Oids, certificate.ExtendedKeyUsage.Count))
            {
                return false;
            }

            return true;
        }

        private static bool ValidateSslCertificateKeyUsage(KeyUsageFlags keyUsageFlags)
        {
            if ((keyUsageFlags & KeyUsageFlags.DigitalSignature) == 0)
            {
                return false;
            }

            //MYK - EC sertifikalarında keyencipherment alani olmayabiliyor, e.g. gmail.com
            if ((keyUsageFlags & KeyUsageFlags.KeyEncipherment) == 0)
            {
                return false;
            }

            return true;
        }

        private static bool ValidateCaCertificateKeyUsage(KeyUsageFlags keyUsageFlags)
        {
            if ((keyUsageFlags & KeyUsageFlags.KeyCertSign) == 0)
            {
                return false;
            }

            if ((keyUsageFlags & KeyUsageFlags.CrlSign) == 0)
            {
                return false;
            }

            return true;
        }

        private static bool ValidateSslCertificateExtendedKeyUsage(byte[][] extendedKeyUsageOiDs, int extendedKeyUsageOidCount)
        {
            //todo: Check for Server Authentication and Client Authentication extended key usage values 
            return true;
        }

        public static bool CheckValidityPeriod(Certificate certificate)
        {
            if (certificate.Validity.NotAfter < 0)
            {
                return false;
            }

            if (certificate.Validity.NotBefore < 0)
            {
                return false;
            }

            //Check  certificate validity perio
            //now always return valid
            //todo: add real implementation code
            return true;
        }

        public static bool CheckValidityPeriodWithCaCertificate(Certificate certificate, Certificate caCertificate)
        {
            if (!CheckValidityPeriod(certificate))
            {
                return false;
            }

            //Check certificate validity period with CA Certificate
            //now always return valid
            //todo: add real implementation code
            return true;
        }
    }
}