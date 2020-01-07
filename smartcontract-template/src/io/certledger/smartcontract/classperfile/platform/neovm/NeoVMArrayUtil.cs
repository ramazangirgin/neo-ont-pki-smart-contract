using Neo.SmartContract.Framework;

namespace CertLedgerBusinessSCTemplate.io.certledger.smartcontract.business
{
    public class NeoVMArrayUtil
    {
        public static byte[] concat(byte[] first, byte[] second)
        {
            return Helper.Concat(first, second);
        }

        public static bool AreEqual(byte[] first, byte[] second)
        {
            return first.Equals(second);
        }
    }
}