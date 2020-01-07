using Neo.SmartContract.Framework;

namespace io.certledger.smartcontract.business
{
    public class CertLedgerBusinessScTemplate : SmartContract
    {
        public static object Main(string operation, params object[] args)
        {
            switch (operation)
            {
                case "AddRootCACertificate":
                {
                    byte[] encodedCert = (byte[]) args[0];
                    byte[] certificateHash = Sha256(encodedCert);
                    byte[] signature = (byte[]) args[1];
                    return RootCaCertificateHandler.AddTrustedRootCaCertificate(certificateHash, encodedCert, signature);
                }
                case "UntrustRootCACertificate":
                {
                    byte[] encodedCert = (byte[]) args[0];
                    byte[] certificateHash = Sha256(encodedCert);
                    byte[] signature = (byte[]) args[1];
                    return RootCaCertificateHandler.UntrustRootCaCertificate(certificateHash, encodedCert, signature);
                }
                case "AddSubCACertificate":
                {
                    byte[] encodedCert = (byte[]) args[0];
                    byte[] certificateHash = Sha256(encodedCert);
                    byte[] signature = (byte[]) args[1];
                    return SubCaCertificateHandler.AddSubCaCertificate(certificateHash, encodedCert, signature);
                }
                case "RevokeSubCACertificate":
                {
                    byte[] encodedCert = (byte[]) args[0];
                    byte[] certificateHash = Sha256(encodedCert);
                    byte[] signature = (byte[]) args[1];
                    return SubCaCertificateHandler.RevokeSubCaCertificate(certificateHash, encodedCert, signature);
                }
                case "AddSSLCertificate":
                {
                    byte[] encodedCert = (byte[]) args[0];
                    byte[] certificateHash = Sha256(encodedCert);
                    return SslCertificateHandler.AddSslCertificate(certificateHash, encodedCert);
                }
                default:
                    return false;
            }
        }
    }
}