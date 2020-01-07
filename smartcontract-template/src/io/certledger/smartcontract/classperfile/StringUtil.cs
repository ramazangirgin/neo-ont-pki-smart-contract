using CertLedgerBusinessSCTemplate;

namespace io.certledger.smartcontract.business.util
{
    public class StringUtil
    {
        public static string ByteArrayToString(byte[] data)
        {
            return NetCoreStringUtil.ByteArrayToString(data);
        }
        
        public static byte[] StringToByteArray(string text)
        {
            return NetCoreStringUtil.StringToByteArray(text);
        }
    }
}