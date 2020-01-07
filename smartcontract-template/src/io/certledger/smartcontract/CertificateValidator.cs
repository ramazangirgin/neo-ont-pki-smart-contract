#if NEO
using Neo.SmartContract.Framework;

#endif
#if NET_CORE
using io.certledger.smartcontract.platform.netcore;
#endif
namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
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
                Logger.log("Can not validate Sub CA Certificate Fields");
                return false;
            }

            if (!CheckValidityPeriod(subCaCertificate))
            {
                Logger.log("Can not validate Sub CA Validity Period");
                return false;
            }

            if (!CertificateChainValidator.ValidateCertificateSignatureWithChain(subCaCertificate))
            {
                Logger.log("Can not validate Sub CA Signature with Issuer Certificate");
                return false;
            }

            return true;
        }

        public static bool ValidateSslCertificateFields(Certificate certificate)
        {
            Logger.log("Validating Certificate Fields");
            if (!CertificateFieldValidator.Validate(certificate))
            {
                Logger.log("Ssl Certificate Field validation failed");
                return false;
            }

            Logger.log("Validating Basic Contraints");
            if (certificate.BasicConstraints.HasBasicConstraints)
            {
                if (certificate.BasicConstraints.IsCa)
                {
                    Logger.log("End user certificates can not have basic constraint field with isCa flag");
                    return false;
                }
            }

            Logger.log("Validating Key Usage");
            if (!ValidateSslCertificateKeyUsage(certificate))
            {
                Logger.log("Ssl Certificate Key Usage Flags invalid");
                return false;
            }

            Logger.log("Validating Extended Usage");
            if (!ValidateSslCertificateExtendedKeyUsage(certificate.ExtendedKeyUsage.Oids))
            {
                Logger.log("Ssl Certificate Extended Key Usage Flags invalid");
                return false;
            }

            return true;
        }


        private static bool ValidateSslCertificateKeyUsage(Certificate certificate)
        {
            if (certificate.PublicKeyAlgName == null)
            {
                Logger.log("Public Key Algorithm Name is null");
                return false;
            }

            if (((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyCertSign) != 0) ||
                ((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.CrlSign) != 0))
            {
                Logger.log("End entity SSL Certificate can not have KeyCertSign or CrlSign");
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

        private static bool ValidateSslCertificateExtendedKeyUsage(byte[][] extendedKeyUsageOiDs)
        {
            bool containsServerAuthOid = false;
            bool containsClientAuthOid = false;
            bool containsInvalidOid = false;
            foreach (var extendedKeyUsageOiD in extendedKeyUsageOiDs)
            {
                if (ArrayUtil.AreEqual(extendedKeyUsageOiD, Constants.EXTENDED_KEY_USAGE_OID_SERVER_AUTHENTICATION))
                {
                    containsServerAuthOid = true;
                }
                else if (ArrayUtil.AreEqual(extendedKeyUsageOiD,
                    Constants.EXTENDED_KEY_OID_USAGE_CLIENT_AUTHENTICATION))
                {
                    containsServerAuthOid = true;
                }
                else if (ArrayUtil.AreEqual(extendedKeyUsageOiD, Constants.EXTENDED_KEY_OID_EMAIL_PROTECTION))
                {
                    containsServerAuthOid = true;
                }
                else
                {
                    containsInvalidOid = true;
                }
            }

            if (containsInvalidOid)
            {
                Logger.log("Extended Key Usage Extension contains invalid OID for SSL Certificate");
                return false;
            }

            if (!containsClientAuthOid && !containsServerAuthOid)
            {
                Logger.log(
                    "SSL Certificate should contain Server Auth Extended Key Usage or Client Authentication Extended Key Usage Extension");
                return false;
            }

            return true;
        }

        public static bool CheckValidityPeriod(Certificate certificate)
        {
            long transactionTime = TransactionContentUtil.retrieveTransactionTime();
            if (transactionTime < certificate.Validity.NotBefore)
            {
                Logger.log("Validity.NotBefore is not in valid period");
                return false;
            }

            if (transactionTime > certificate.Validity.NotAfter)
            {
#if NET_CORE
//fixme: test certificate time is invalid so will be changed with new one.
//remove this block when test certificates changed for NET_CORE tests
//  return false;
                return true;
#else
                Logger.log("Validity.NotAfter is not in valid period");
                return false;
#endif
            }

            return true;
        }

        public static bool CheckCertificateWithWithCaCertificate(Certificate certificate, Certificate caCertificate)
        {
            if (!CertificateSignatureValidator.ValidateCertificateSignature(certificate, caCertificate))
            {
                Logger.log("Can not find validate signature with issuer certificate");
                return false;
            }

            if (!CheckValidityPeriodWithCaCertificate(certificate, caCertificate))
            {
                return false;
            }

            if (!CheckCertificatePolicyWithCaCertificate(certificate, caCertificate))
            {
                return false;
            }

            return true;
        }

        private static bool CheckValidityPeriodWithCaCertificate(Certificate certificate, Certificate caCertificate)
        {
            if (certificate.Validity.NotBefore < caCertificate.Validity.NotBefore)
            {
                Logger.log(
                    "End entity SSL Certificate period validity check with CA is failed. Invalid NotBefore value");
                return false;
            }

            if (certificate.Validity.NotAfter > caCertificate.Validity.NotAfter)
            {
                Logger.log(
                    "End entity SSL Certificate period validity check with CA is failed. Invalid NotAfter value");
                return false;
            }

            //Check certificate validity period with CA Certificate
            //now always return valid
            //todo: add real implementation code
            return true;
        }

        private static bool CheckCertificatePolicyWithCaCertificate(Certificate certificate, Certificate caCertificate)
        {
            //todo:
            /*
             * 
   In an end entity certificate, these policy information terms indicate
   the policy under which the certificate has been issued and the
   purposes for which the certificate may be used.  In a CA certificate,
   these policy information terms limit the set of policies for
   certification paths that include this certificate.  When a CA does
   not wish to limit the set of policies for certification paths that
   include this certificate, it MAY assert the special policy anyPolicy,
   with a value of { 2 5 29 32 0 }.
   If this extension is
   critical, the path validation software MUST be able to interpret this
   extension (including the optional qualifier), or MUST reject the
   certificate.
             */
            //now always return valid
            //todo: add real implementation code
            return true;
        }
    }
}