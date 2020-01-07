using Neo.SmartContract.Framework;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo
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