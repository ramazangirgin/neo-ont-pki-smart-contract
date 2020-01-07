using Neo.SmartContract.Framework.Services.Neo;

namespace CertLedgerBusinessSCTemplate.io.certledger.smartcontract.business.platform.neovm
{
    public class NeoVMLogger
    {
        public static void log(string message)
        {
            Runtime.Log(message);
        }
    }
}