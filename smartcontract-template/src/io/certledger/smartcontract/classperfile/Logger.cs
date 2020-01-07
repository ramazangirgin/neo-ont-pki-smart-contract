using CertLedgerBusinessSCTemplate.io.certledger.smartcontract.business.platform.neovm;

namespace CertLedgerBusinessSCTemplate.io.certledger.smartcontract.business
{
    public class Logger
    {
        public static void log(string message)
        {
            NetCoreLogger.log(message);
        }
    }
}