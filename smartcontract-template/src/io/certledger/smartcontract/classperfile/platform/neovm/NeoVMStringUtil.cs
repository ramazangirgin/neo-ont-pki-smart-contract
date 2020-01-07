using Neo.SmartContract.Framework;

namespace io.certledger.smartcontract.business.util
{
    public class NeoVMStringUtil
    {
        public static string ByteArrayToString(byte[] data)
        {
            return Helper.AsString(data);
        }
        
        public static byte[] StringToByteArrayToString(string text)
        {
            return Helper.AsByteArray(text);
        }
    }
}