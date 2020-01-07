using Neo.SmartContract.Framework;

namespace io.certledger.smartcontract.business.util
{
    public class NeoVMSerializationUtil
    {
        public static byte[] Serialize(object source)
        {
            return Helper.Serialize(source);
        }

        public static object Deserialize(byte[] source)
        {
            return Helper.Deserialize(source);
        }
    }
}