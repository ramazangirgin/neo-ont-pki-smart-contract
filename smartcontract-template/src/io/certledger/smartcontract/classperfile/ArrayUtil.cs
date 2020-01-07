namespace CertLedgerBusinessSCTemplate.io.certledger.smartcontract.business
{
    public class ArrayUtil
    {
        public static byte[] Concat(byte[] first, byte[] second)
        {
            //return NeoVMArrayUtil.concat(first, second);
            return NetCoreArrayUtil.concat(first, second);
        }
        
        public static bool AreEqual(byte[] first, byte[] second)
        {
            //return NeoVMArrayUtil.concat(first, second);
            return NetCoreArrayUtil.AreEqual(first, second);
        }
    }
}