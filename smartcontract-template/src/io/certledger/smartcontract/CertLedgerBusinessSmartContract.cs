#if NEO
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo;
using CertLedgerBusinessSCTemplate_NeoVM.io.certledger.smartcontract;
using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.ont
{
    public class CertLedgerBusinessSmartContract : SmartContract
    {
        [Appcall("693af31bdc6f7e0241f2bba29078fe469b26ec7c")]
        public static extern object CertCreditMethodCall(string method, object[] arr);

        public static object Main(string operation, params object[] args)
        {
            if (operation.Equals("AddRootCACertificate"))
            {
                Logger.log("Operation", "AddRootCACertificate");
                return AddRootCACertificate(args);
            }
            else if (operation.Equals("UntrustRootCACertificate"))
            {
                Logger.log("Operation", "UntrustRootCACertificate");
                return UntrustRootCACertificate(args);
            }
            else if (operation.Equals("AddSubCACertificate"))
            {
                return AddSubCACertificate(args);
            }
            else if (operation.Equals("RevokeSubCACertificate"))
            {
                return RevokeSubCACertificate(args);
            }
            else if (operation.Equals("AddSSLCertificate"))
            {
                return AddSSLCertificate(args);
            }
            else if (operation.Equals("RevokeSSLCertificate"))
            {
                return RevokeSSLCertificate(args);
            }
            else if (operation.Equals("ReportFraud"))
            {
                return ReportFraud(args);
            }
            else if (operation.Equals("ApproveFraudReport"))
            {
                return ApproveFraudReport(args);
            }
            else if (operation.Equals("RejectFraudReport"))
            {
                return RejectFraudReport(args);
            }
            else if (operation.Equals("LogDomainCertificates"))
            {
                return LogDomainCertificates(args);
            }
#if SMART_CONTRACT_TEST
            else if (operation.Equals("LogSSLCertificateStorageStatus"))
            {
                return LogSSLCertificateStorageStatus(args);
            }
            else if (operation.Equals("LogCACertificateStorageStatus"))
            {
                return LogCACertificateStorageStatus(args);
            }
            else if (operation.Equals("LogTrustedCAList"))
            {
                return LogTrustedCAList();
            }
            else if (operation.Equals("ResetStorage"))
            {
                return ResetStorage();
            }
            else if (operation.Equals("ParseCertificate"))
            {
                Logger.log("Operation", "ParseCertificate");
                return ParseCertificate(args);
            }
            else if (operation.Equals("VerifyCertificateSignature"))
            {
                Logger.log("Operation", "VerifyCertificateSignature");
                return VerifyCertificateSignature(args);
            }
            else if (operation.Equals("Destroy"))
            {
                Logger.log("Operation", "Destroy");
                return Destroy(args);
            }
            else if (operation.Equals("LogFraudReportStatus"))
            {
                return LogFraudReportStatus(args);
            }
#endif
            Logger.log("Operation", "Unknown");
            return false;
        }

        public static object Destroy(object[] args)
        {
            Logger.log("Destroying Smart Contract");
            Neo.SmartContract.Framework.Services.Neo.Contract.Destroy();
            Logger.log("Destroyed Smart Contract");
            return true;
        }

        public static object ParseCertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            Logger.log("ParseCertificate  started");
            Certificate certificate = CertificateParser.Parse(encodedCert);
            Logger.LogCertificate(certificate);
            Logger.log("ParseCertificate finished");
            return true;
        }

        public static object VerifyCertificateSignature(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] encodedIssuerCert = (byte[]) args[1];
            Logger.log("VerifyCertificateSignature started");
            bool result = NeoVMSignatureValidator.CheckCertificateSignature(encodedCert, encodedIssuerCert);
            Logger.log("VerifyCertificateSignature finished");
            Logger.log(result);
            return result;
        }

        public static object AddRootCACertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            Logger.log("Adding Root CA Certificate started");
            byte[] requestSignature = (byte[]) args[1];
            bool result =
                RootCaCertificateHandler.AddTrustedRootCaCertificate(certificateHash, encodedCert, requestSignature);
            Logger.log("Adding Root CA Certificate completed");
            Logger.log(result);
            return result;
        }

        public static object UntrustRootCACertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            Logger.log("Untrusting Root CA Certificate started");
            byte[] requestSignature = (byte[]) args[1];
            bool result =
                RootCaCertificateHandler.UntrustRootCaCertificate(certificateHash, encodedCert, requestSignature);
            Logger.log("Untrusting Root CA Certificate completed");
            Logger.log(result);
            return result;
        }

        public static object AddSubCACertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            byte[] signature = (byte[]) args[1];
            Logger.log("Adding Sub CA Certificate");
            bool addSubCaCertificateResult =
                SubCaCertificateHandler.AddSubCaCertificate(certificateHash, encodedCert, signature);
            Logger.log(addSubCaCertificateResult);
            Logger.log("Sub CA Certificate process completed");
            return addSubCaCertificateResult;
        }

        public static object RevokeSubCACertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            Logger.log("Revoke Sub CA Certificate started");
            byte[] signature = (byte[]) args[1];
            bool result = SubCaCertificateHandler.RevokeSubCaCertificate(certificateHash, encodedCert, signature);
            Logger.log("Revoke Sub CA Certificate completed");
            Logger.log("Result : ", result);
            return result;
        }

        public static object AddSSLCertificate(object[] args)
        {
            byte[] accountAddress = (byte[]) args[0];
            Logger.log(accountAddress);
            Logger.log("Checking Account Owner with CheckWitness");
            if (!Runtime.CheckWitness(accountAddress))
            {
                Logger.log("Invalid Account or Invalid Transaction");
                return false;
            }

            Logger.log("Checked Account Owner with CheckWitness");

            Logger.log("Checking Account Cert Credit Balance");
            if (!PaymentManager.IsAccountBalanceSufficientCertificateOperation(accountAddress))
            {
                Logger.log("Account Cert Credit is Not Sufficient for Add SSL Certificate Operation");
                return false;
            }

            Logger.log("Checked Account Cert Credit Balance");

            byte[] encodedCert = (byte[]) args[1];
            byte[] certificateHash = Sha256(encodedCert);
            Logger.log("Adding SSL Certificate");
            bool addSslCertificateResult = SslCertificateHandler.AddSslCertificate(certificateHash, encodedCert);

            if (addSslCertificateResult)
            {
                Logger.log("Charging Fee For Certificate Operation");
                if (!PaymentManager.ChargeFeeForCertificateOperation(accountAddress))
                {
                    Logger.log("Error while charging fee for Certificate Operation");
                    return false;
                }

                Logger.log("Charge Fee For Certificate Operation success");

                EventNotifier.NotifyNewSSLCertificateAdded(encodedCert);
            }
            else
            {
                Logger.log(
                    "Because of error in add in SSL Certificate Not Fee will be charged For Certificate Operation");
            }

            Logger.log(addSslCertificateResult);
            Logger.log("SSL Certificate process completed");
            return addSslCertificateResult;
        }

        public static object RevokeSSLCertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            Logger.log("Revoke SSL Certificate started");
            byte[] signature = (byte[]) args[1];
            bool result = SslCertificateHandler.RevokeSslCertificate(certificateHash, encodedCert, signature);
            Logger.log("Revoke SSL Certificate completed");
            Logger.log("Result : ", result);
            return result;
        }

        public static object ReportFraud(object[] args)
        {
            Logger.log("Report Fraud Operation started");

            byte[] fraudId = (byte[]) args[0];
            byte[] fakeButValidCertificateBytes = (byte[]) args[1];
            byte[] fakeButValidCertificateHash = Sha256(fakeButValidCertificateBytes);
            byte[] signerCertificateBytes = (byte[]) args[2];
            byte[] signerCertificateBytesHash = Sha256(fakeButValidCertificateBytes);
            byte[] signature = (byte[]) args[3];

            bool result = FraudHandler.ReportFraud(fraudId, fakeButValidCertificateBytes, fakeButValidCertificateHash,
                signerCertificateBytes, signerCertificateBytesHash, signature);
            Logger.log("Report Fraud Operation completed");
            Logger.log("Result : ", result);
            return result;
        }

        public static object ApproveFraudReport(object[] args)
        {
            Logger.log("Approve Fraud Operation started");

            byte[] fraudId = (byte[]) args[0];
            byte[] signature = (byte[]) args[1];

            bool result = FraudHandler.ApproveFraudReport(fraudId, signature);
            Logger.log("Approve Fraud Operation completed");
            Logger.log("Result : ", result);
            return result;
        }

        public static object RejectFraudReport(object[] args)
        {
            Logger.log("Reject Fraud Operation started");

            byte[] fraudId = (byte[]) args[0];
            byte[] signature = (byte[]) args[1];

            bool result = FraudHandler.RejectFraudReport(fraudId, signature);
            Logger.log("Reject Fraud Operation completed");
            Logger.log("Result : ", result);
            return result;
        }

        public static object LogDomainCertificates(object[] args)
        {
            byte[] domainCertListStorageKey = (byte[]) args[0];
            Logger.log("Log Domain Certificates started. Domain: ", domainCertListStorageKey);
            byte[] trustedRootCAListHashMapEntrySerialized = StorageUtil.readFromStorage(domainCertListStorageKey);
            if (trustedRootCAListHashMapEntrySerialized != null)
            {
                Logger.log("Certificates for domain exists in Storage. Domain: ", domainCertListStorageKey);
                CertificateHashMapEntry certificateHashMapEntry =
                    (CertificateHashMapEntry) SerializationUtil.Deserialize(trustedRootCAListHashMapEntrySerialized);
                Logger.log("Certificate Count: ");
                Logger.log(certificateHashMapEntry.certificateHashArray.Length);

                for (int i = 0; i < certificateHashMapEntry.certificateHashArray.Length; i++)
                {
                    byte[] certificateHashEntrySerialized = certificateHashMapEntry.certificateHashArray[i];
                    CertificateHashEntry certificateHashEntry =
                        (CertificateHashEntry) SerializationUtil.Deserialize(certificateHashEntrySerialized);
                    Logger.log("IsCa: ", certificateHashEntry.IsCa);
                    Logger.log(certificateHashEntry.CertificateHash);
                    LogSSLCertificateWithCertificateHashValue(certificateHashEntry.CertificateHash);
                }
            }
            else
            {
                Logger.log("There isn't any certificate for Domain: ", domainCertListStorageKey);
            }

            Logger.log("Log Domain Certificates completed. Domain: ", domainCertListStorageKey);
            return true;
        }

        public static object LogCACertificateStorageStatus(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            byte[] caCertificateEnrtySerialized = StorageUtil.readFromStorage(certificateHash);
            if (caCertificateEnrtySerialized != null)
            {
                CaCertificateEntry caCertificateHashEntry =
                    (CaCertificateEntry) SerializationUtil.Deserialize(caCertificateEnrtySerialized);
                Logger.log("CA Certificate Exists in Storage");
                Logger.log(caCertificateHashEntry.CertificateValue);
                Logger.log("IsRevoked: ", caCertificateHashEntry.IsRevoked);
                Logger.log("IsTrusted: ", caCertificateHashEntry.IsTrusted);
            }
            else
            {
                Logger.log("CA Certificate Not Exists in Storage");
            }

            return true;
        }

        public static object LogFraudReportStatus(object[] args)
        {
            byte[] fraudId = (byte[]) args[0];
            FraudEntry fraudEntry = FraudStorageManager.ReadFraudEntry(fraudId);
            if (fraudEntry.FraudId == null)
            {
                Logger.log("Can not find Fraud Report");
            }
            else
            {
                Logger.log("Fraud Report Exists in Storage");
                Logger.log(fraudEntry.FraudId);
                Logger.log(fraudEntry.FakeButValidCertificateHash);
                Logger.log(fraudEntry.Reporter);
                Logger.log(fraudEntry.Status);
            }

            return true;
        }

        public static object LogSSLCertificateStorageStatus(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            LogSSLCertificateWithCertificateHashValue(certificateHash);
            return true;
        }

        private static void LogSSLCertificateWithCertificateHashValue(byte[] certificateHash)
        {
            byte[] certificateEnrtySerialized = StorageUtil.readFromStorage(certificateHash);
            if (certificateEnrtySerialized != null)
            {
                EndEntityCertificateEntry endEntityCertificateEntry =
                    (EndEntityCertificateEntry) SerializationUtil.Deserialize(certificateEnrtySerialized);
                Logger.log("SSL Certificate Exists in Storage");
                Logger.log("IsRevoked: ", endEntityCertificateEntry.IsRevoked);
                Logger.log(endEntityCertificateEntry.CertificateValue);
            }
            else
            {
                Logger.log("SSL Certificate Not Exists in Storage");
            }
        }

        public static object LogTrustedCAList()
        {
            CertificateHashEntry[] retrieveTrustedRootCaList = CertificateStorageManager.RetrieveTrustedRootCaList();
            Logger.log(retrieveTrustedRootCaList.Length);
            foreach (CertificateHashEntry certificateHashEntry in retrieveTrustedRootCaList)
            {
                Logger.log("                                     ");
                Logger.log(certificateHashEntry.CertificateHash);
                Logger.log(certificateHashEntry.IsCa);
                Logger.log("                                     ");
            }

            return true;
        }

        public static object ResetStorage()
        {
            Logger.log("Deleting all storage entries");
            StorageUtil.clearStorage();
            Logger.log("Deleted all storage entries");
            return true;
        }
    }
}
#endif