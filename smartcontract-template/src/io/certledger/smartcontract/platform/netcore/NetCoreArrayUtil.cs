using Org.BouncyCastle.Utilities;

namespace io.certledger.smartcontract.platform.netcore
{
    public class NetCoreArrayUtil
    {
        public static byte[] concat(byte[] first, byte[] second)
        {
            return Arrays.Concatenate(first, second);
        }

        public static bool AreEqual(byte[] first, byte[] second)
        {
            return Arrays.AreEqual(first, second);
        }
    }
}