using System.Diagnostics;

namespace CertLedgerBusinessSCTemplate.io.certledger.smartcontract.business.platform.neovm
{
    public class NetCoreLogger
    {
        public static void log(string message)
        {
            Trace.WriteLine(message);
        }
    }
}