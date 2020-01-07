#if NEO
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo;
using Neo.SmartContract.Framework;

#endif
#if NET_CORE
using io.certledger.smartcontract.platform.netcore;

#endif
namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class SignatureValidator
    {
#if NEO
//fixme: CHANGE in production environment
        static readonly byte[] ROOT_CA_REQUEST_SIGNATURE_VALIDATION_PUBLIC_KEY_SUBJECT_PUBLIC_KEY_INFO =
            "3076301006072a8648ce3d020106052b81040022036200042dfe424daf556803bf03df26a46f8b28d6eb84efb397334253b8986ac9591adbbe8b64fc23f15d2be0578ba1fa05bfbb7fa463f5a201e69d108f2e932243d7d8190de0d7caf4d2df16bf32c9e056c5ce83be39ba91675b3af09e8c164bed3571"
                .HexToBytes();

        private static readonly byte[] OPERATION_ADD_TRUSTED_ROOT_CA_CERTIFICATE =
            "4144445f545255535445445f524f4f545f43415f4345525449464943415445".HexToBytes();

        private static readonly byte[] OPERATION_UNTRUST_ROOT_CA_CERTIFICATE =
            "554e54525553545f524f4f545f43415f4345525449464943415445".HexToBytes();

        private static readonly byte[] OPERATION_REVOKE_SSL_CERTIFICATE =
            "5245564f4b455f53534c5f4345525449464943415445".HexToBytes();

        private static readonly byte[] OPERATION_ADD_SUBCA_CERTIFICATE =
            "4144445f53554243415f4345525449464943415445".HexToBytes();

        private static readonly byte[] OPERATION_REVOKE_SUBCA_CERTIFICATE =
            "5245564f4b455f53554243415f4345525449464943415445".HexToBytes();

        private static readonly byte[] OPERATION_REPORT_FRAUD_CERTIFICATE =
            "4f5045524154494f4e5f5245504f52545f4652415544".HexToBytes();

        private static readonly byte[] OPERATION_APPROVE_FRAUD_REPORT =
            "4f5045524154494f4e5f415050524f56455f46524155445f5245504f5254".HexToBytes();

        private static readonly byte[] OPERATION_REJECT_FRAUD_REPORT =
            "4f5045524154494f4e5f52454a4543545f46524155445f5245504f5254".HexToBytes();

#endif
#if NET_CORE
//fixme: CHANGE in production environment
        static readonly byte[] ROOT_CA_REQUEST_SIGNATURE_VALIDATION_PUBLIC_KEY_SUBJECT_PUBLIC_KEY_INFO =
            HexUtil.HexStringToByteArray(
                "3076301006072a8648ce3d020106052b81040022036200042dfe424daf556803bf03df26a46f8b28d6eb84efb397334253b8986ac9591adbbe8b64fc23f15d2be0578ba1fa05bfbb7fa463f5a201e69d108f2e932243d7d8190de0d7caf4d2df16bf32c9e056c5ce83be39ba91675b3af09e8c164bed3571");

        private static readonly byte[] OPERATION_ADD_TRUSTED_ROOT_CA_CERTIFICATE =
            HexUtil.HexStringToByteArray("4144445f545255535445445f524f4f545f43415f4345525449464943415445");

        private static readonly byte[] OPERATION_UNTRUST_ROOT_CA_CERTIFICATE =
            HexUtil.HexStringToByteArray("554e54525553545f524f4f545f43415f4345525449464943415445");

        private static readonly byte[] OPERATION_REVOKE_SSL_CERTIFICATE =
            HexUtil.HexStringToByteArray("5245564f4b455f53534c5f4345525449464943415445");

        private static readonly byte[] OPERATION_ADD_SUBCA_CERTIFICATE =
            HexUtil.HexStringToByteArray("4144445f53554243415f4345525449464943415445");

        private static readonly byte[] OPERATION_REVOKE_SUBCA_CERTIFICATE =
            HexUtil.HexStringToByteArray("5245564f4b455f53554243415f4345525449464943415445"); 
    
        private static readonly byte[] OPERATION_REPORT_FRAUD_CERTIFICATE =
            HexUtil.HexStringToByteArray("4f5045524154494f4e5f5245504f52545f4652415544"); 
    
        private static readonly byte[] OPERATION_APPROVE_FRAUD_REPORT =
            HexUtil.HexStringToByteArray("4f5045524154494f4e5f415050524f56455f46524155445f5245504f5254");
    
        private static readonly byte[] OPERATION_REJECT_FRAUD_REPORT =
            HexUtil.HexStringToByteArray("4f5045524154494f4e5f52454a4543545f46524155445f5245504f5254");

#endif
        const int NATIVE_CONTRACT_ECDSAWithSHA256_ALG_CODE = 10;
        const int NATIVE_CONTRACT_SHA256WithRSAPSS_ALG_CODE = 13;

        public static bool CheckAddTrustedRootCARequestSignature(byte[] signature, byte[] signed)
        {
#if NEO
            byte[] dataForSign = ArrayUtil.Concat(OPERATION_ADD_TRUSTED_ROOT_CA_CERTIFICATE, signed);
            return NeoVMSignatureValidator.CheckSignature(NATIVE_CONTRACT_ECDSAWithSHA256_ALG_CODE, signature,
                dataForSign,
                ROOT_CA_REQUEST_SIGNATURE_VALIDATION_PUBLIC_KEY_SUBJECT_PUBLIC_KEY_INFO);
#endif
#if NET_CORE
            byte[] dataForSign = ArrayUtil.Concat(OPERATION_ADD_TRUSTED_ROOT_CA_CERTIFICATE, signed);
            return NetCoreSignatureValidator.CheckECDSASha256Signature(signature, dataForSign,
                ROOT_CA_REQUEST_SIGNATURE_VALIDATION_PUBLIC_KEY_SUBJECT_PUBLIC_KEY_INFO);
#endif
        }

        public static bool CheckUntrustRootCARequestSignature(byte[] signature, byte[] signed)
        {
#if NEO
            byte[] dataForSign = ArrayUtil.Concat(OPERATION_UNTRUST_ROOT_CA_CERTIFICATE, signed);
            return NeoVMSignatureValidator.CheckSignature(NATIVE_CONTRACT_ECDSAWithSHA256_ALG_CODE, signature,
                dataForSign,
                ROOT_CA_REQUEST_SIGNATURE_VALIDATION_PUBLIC_KEY_SUBJECT_PUBLIC_KEY_INFO);
#endif
#if NET_CORE
            byte[] dataForSign = ArrayUtil.Concat(OPERATION_UNTRUST_ROOT_CA_CERTIFICATE, signed);
            return NetCoreSignatureValidator.CheckECDSASha256Signature(signature, dataForSign,
                ROOT_CA_REQUEST_SIGNATURE_VALIDATION_PUBLIC_KEY_SUBJECT_PUBLIC_KEY_INFO);
#endif
        }

        public static bool CheckRevokeSSLCertificateRequestSignature(byte[] signature, Certificate sslCertificate,
            Certificate signerCertificate)
        {
            return CheckCertificateOperationRequestSignature(OPERATION_REVOKE_SSL_CERTIFICATE, signature,
                sslCertificate, signerCertificate);
        }

        public static bool CheckAddSubCACertificateRequestSignature(byte[] signature, Certificate subCaCertificate,
            Certificate signerCertificate)
        {
            return CheckCertificateOperationRequestSignature(OPERATION_ADD_SUBCA_CERTIFICATE, signature,
                subCaCertificate, signerCertificate);
        }

        public static bool CheckRevokeSubCACertificateRequestSignature(byte[] signature, Certificate subCACertificate,
            Certificate signerCertificate)
        {
            return CheckCertificateOperationRequestSignature(OPERATION_REVOKE_SUBCA_CERTIFICATE, signature,
                subCACertificate, signerCertificate);
        }

        public static bool CheckReportFraudRequestSignature(byte[] signature, Certificate fakeButValidCertificate,
            Certificate signerCertificate)
        {
            return CheckCertificateOperationRequestSignature(OPERATION_REPORT_FRAUD_CERTIFICATE, signature,
                fakeButValidCertificate, signerCertificate);
        }

        public static bool CheckApproveFraudRequestSignature(byte[] fraudId, byte[] signature)
        {
            byte[] operation = OPERATION_APPROVE_FRAUD_REPORT;
            byte[] dataForSign = ArrayUtil.Concat(operation, fraudId);
            Logger.log("[Smart Contract]-Data For Sign (For Approve Fraud)");
            Logger.log((dataForSign));

#if NEO
            Logger.log("[Smart Contract]Signature Value (For Approve Fraud)");
            Logger.log((signature));
            return NeoVMSignatureValidator.CheckSignature(NATIVE_CONTRACT_ECDSAWithSHA256_ALG_CODE, signature,
                dataForSign,
                ROOT_CA_REQUEST_SIGNATURE_VALIDATION_PUBLIC_KEY_SUBJECT_PUBLIC_KEY_INFO);

#endif
#if NET_CORE
            return NetCoreSignatureValidator.CheckECDSASha256Signature(signature, dataForSign,
                ROOT_CA_REQUEST_SIGNATURE_VALIDATION_PUBLIC_KEY_SUBJECT_PUBLIC_KEY_INFO);
#endif
        }

        public static bool CheckRejectFraudRequestSignature(byte[] fraudId, byte[] signature)
        {
            byte[] operation = OPERATION_REJECT_FRAUD_REPORT;
            byte[] dataForSign = ArrayUtil.Concat(operation, fraudId);

#if NEO
            return NeoVMSignatureValidator.CheckSignature(NATIVE_CONTRACT_ECDSAWithSHA256_ALG_CODE, signature,
                dataForSign,
                ROOT_CA_REQUEST_SIGNATURE_VALIDATION_PUBLIC_KEY_SUBJECT_PUBLIC_KEY_INFO);

#endif
#if NET_CORE
            return NetCoreSignatureValidator.CheckECDSASha256Signature(signature, dataForSign,
                ROOT_CA_REQUEST_SIGNATURE_VALIDATION_PUBLIC_KEY_SUBJECT_PUBLIC_KEY_INFO);
#endif
        }

        public static bool CheckCertificateOperationRequestSignature(byte[] operation, byte[] signature,
            Certificate certificate, Certificate signerCertificate)
        {
            byte[] dataForSign = ArrayUtil.Concat(operation, certificate.EncodedValue);
            if (ArrayUtil.Contains(signerCertificate.PublicKeyAlgName, Constants.ALG_NAME_RSA_UPPERCASE) ||
                ArrayUtil.Contains(signerCertificate.PublicKeyAlgName, Constants.ALG_NAME_RSA_LOWERCASE))
            {
#if NET_CORE
                return NetCoreSignatureValidator.CheckRSAPSSSha256Signature(signature, dataForSign,
                    signerCertificate.SubjectPublicKeyInfo);
#endif
#if NEO
                return NeoVMSignatureValidator.CheckSignature(NATIVE_CONTRACT_SHA256WithRSAPSS_ALG_CODE, signature,
                    dataForSign,
                    signerCertificate.SubjectPublicKeyInfo);
#endif
            }
            else if (ArrayUtil.Contains(signerCertificate.PublicKeyAlgName, Constants.ALG_NAME_EC_UPPERCASE) ||
                     ArrayUtil.Contains(signerCertificate.PublicKeyAlgName, Constants.ALG_NAME_EC_LOWERCASE))
            {
#if NET_CORE
                return NetCoreSignatureValidator.CheckECDSASha256Signature(signature, dataForSign,
                    signerCertificate.SubjectPublicKeyInfo);
#endif
#if NEO
                return NeoVMSignatureValidator.CheckSignature(NATIVE_CONTRACT_ECDSAWithSHA256_ALG_CODE, signature,
                    dataForSign,
                    signerCertificate.SubjectPublicKeyInfo);
#endif
            }

            Logger.log("Unknown Certificate Public Key Algorithm");
            Logger.log(signerCertificate.PublicKeyAlgName);
            return false;
        }
    }
}