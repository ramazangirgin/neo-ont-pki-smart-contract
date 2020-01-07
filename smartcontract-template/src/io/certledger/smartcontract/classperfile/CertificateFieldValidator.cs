using io.certledger.smartcontract.business;

namespace CertLedgerBusinessSCTemplate.io.certledger.smartcontract.business
{
    public class CertificateFieldValidator
    {
        public static bool Validate(Certificate certificate)
        {
            if (!IsVersion3(certificate))
            {
                Logger.log("Validation Error: Is Not v3 Certificate");
                return false;
            }

            if (!SignatureAlgorithmFieldIsSameWithTBSCertificateSignatureAlgorithmField(certificate))
            {
                Logger.log("Validation Error: Signature field is not same with TBS Signature Field");
                return false;
            }

            //todo: discuss about 
           /* if (!IsSerialNumberPositive(certificate))
            {
                Logger.log("Validation Error: Serial Number is not positive");
                return false;
            }
            */

            if (IsIssuerEmpty(certificate))
            {
                Logger.log("Validation Error: All Issuer Name Fields is empty or null");
                return false;
            }

            return true;
        }

        private static bool IsVersion3(Certificate certificate)
        {
            return certificate.Version == 3;
        }

        private static bool SignatureAlgorithmFieldIsSameWithTBSCertificateSignatureAlgorithmField(Certificate certificate)
        {
            return ArrayUtil.AreEqual(certificate.SignatureAlgorithm, certificate.TBSSignatureAlgorithm);
        }

        private static bool IsSerialNumberPositive(Certificate certificate)
        {
            return certificate.SerialNumber.Sign > 0;
        }

        private static bool IsIssuerEmpty(Certificate certificate)
        {
            return certificate.Issuer.isEmpty;
        }
    }
}