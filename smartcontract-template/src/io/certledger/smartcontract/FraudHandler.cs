namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class FraudHandler
    {
        public static bool ReportFraud(byte[] fraudId, byte[] fakeButValidCertificateBytes,
            byte[] fakeButValidCertificateHash,
            byte[] signerCertificateBytes, byte[] signerCertificateBytesHash, byte[] signature)
        {
            Certificate fakeButValidCertificate = CertificateParser.Parse(fakeButValidCertificateBytes);
            if (!fakeButValidCertificate.IsLoaded)
            {
                Logger.log("Can not parse Fake But Valid SSL Certificate");
                return false;
            }

            EndEntityCertificateEntry fakeButValidCertificateEntry =
                CertificateStorageManager.RetrieveEndEntityCertificateFromStorage(fakeButValidCertificateHash);
            if (fakeButValidCertificateEntry.CertificateValue == null)
            {
                Logger.log("Can not find Fake But Valid SSL Certificate");
                return false;
            }

            if (fakeButValidCertificateEntry.IsRevoked)
            {
                Logger.log("Fake But Valid SSL Certificate is revoked before");
                return false;
            }

            Certificate signerCertificate = CertificateParser.Parse(signerCertificateBytes);
            if (!signerCertificate.IsLoaded)
            {
                Logger.log("Can not parse Signer Certificate");
                return false;
            }

            var signerCertificateContainFakeButValidCertificateDnsEntry =
                checkDnsValues(fakeButValidCertificate, signerCertificate);

            if (!signerCertificateContainFakeButValidCertificateDnsEntry)
            {
                Logger.log("Signer Certificate Does not contain required DNS value");
                return false;
            }

            Logger.log("Starting Validate Signature For Report Fraud Request");
            bool signatureValidationResult =
                SignatureValidator.CheckReportFraudRequestSignature(signature, fakeButValidCertificate,
                    signerCertificate);
            if (!signatureValidationResult)
            {
                Logger.log("Report Fraud Request signature Invalid");
                return false;
            }

            Logger.log("Validated Signature For Report Fraud Request");

            FraudStorageManager.AddFraudReportToStorage(fraudId, signerCertificateBytes, fakeButValidCertificateHash);
            //todo: add fraud notification after log infrastructure fixed

            return true;
        }

        public static bool ApproveFraudReport(byte[] fraudId, byte[] signature)
        {
            FraudEntry fraudEntry = FraudStorageManager.ReadFraudEntry(fraudId);
            if (fraudEntry.FraudId == null)
            {
                Logger.log("Can not find fraud with Id");
                return false;
            }
            
            if (fraudEntry.Status!=FraudStatus.REPORTED)
            {  
                Logger.log("Invalid Fraud Report Status");
                return false;
            }

            Logger.log("Starting Validate Signature For Report Approve Request");
            bool signatureValidationResult =
                SignatureValidator.CheckApproveFraudRequestSignature(fraudId, signature);
            if (!signatureValidationResult)
            {
                Logger.log("Approve Fraud Request signature Invalid");
                return false;
            }
            Logger.log("Validated Signature For Approve Fraud Request");

            fraudEntry.Status = FraudStatus.APPROVED;
            fraudEntry.ApproveRejectOperationDate = TransactionContentUtil.retrieveTransactionTime();
            FraudStorageManager.updateFraudEntry(fraudEntry);
            //todo: add fraud notification after log infrastructure fixed

            return true;
        }

        
        public static bool RejectFraudReport(byte[] fraudId, byte[] signature)
        {
            FraudEntry fraudEntry = FraudStorageManager.ReadFraudEntry(fraudId);
            if (fraudEntry.FraudId == null)
            {
                Logger.log("Can not find fraud with Id");
                return false;
            }

            if (fraudEntry.Status != FraudStatus.REPORTED)
            {
                Logger.log("Invalid Fraud Report Status");
                return false;
            }

            Logger.log("Starting Validate Signature For Report Rejection Request");
            bool signatureValidationResult =
                SignatureValidator.CheckRejectFraudRequestSignature(fraudId, signature);
            if (!signatureValidationResult)
            {
                Logger.log("Approve Fraud Request signature Invalid");
                return false;
            }
            Logger.log("Validated Signature For Reject Fraud Request");

            fraudEntry.Status = FraudStatus.REJECTED;
            fraudEntry.ApproveRejectOperationDate = TransactionContentUtil.retrieveTransactionTime();
            FraudStorageManager.updateFraudEntry(fraudEntry);
            //todo: add fraud notification after log infrastructure fixed
            return true;
        }

        private static bool checkDnsValues(Certificate fakeButValidCertificate, Certificate signerCertificate)
        {
            bool signerCertificateContainFakeButValidCertificateDnsEntry = false;

            foreach (byte[] fakeButValidCertificateDnsName in fakeButValidCertificate.DNsNames)
            {
                foreach (byte[] signerCertificateDNsName in signerCertificate.DNsNames)
                {
                    if (ArrayUtil.AreEqual(signerCertificateDNsName, fakeButValidCertificateDnsName))
                    {
                        signerCertificateContainFakeButValidCertificateDnsEntry = true;
                    }
                }
            }

            return signerCertificateContainFakeButValidCertificateDnsEntry;
        }
    }
}