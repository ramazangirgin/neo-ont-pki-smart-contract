#if NEO
using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class EventNotifier
    {
        private static readonly byte[] EVENT_NOTIFICATION =
            "4556454e545f4e4f54494649434154494f4e".HexToBytes();

        private static readonly byte[] EVENT_NEW_SSL_CERTIFICATE_ADDED =
            "4556454e545f4e45575f53534c5f43455254494649434154455f4144444544".HexToBytes();

        public static void NotifyNewSSLCertificateAdded(byte[] encodedCertificate)
        {
            Logger.log("Sending Notification For EVENT_NEW_SSL_CERTIFICATE_ADDED Event");
            Runtime.Notify(EVENT_NOTIFICATION, EVENT_NEW_SSL_CERTIFICATE_ADDED, encodedCertificate);
            Logger.log("Sent Notification For EVENT_NEW_SSL_CERTIFICATE_ADDED Event");
        }
    }
}
#endif