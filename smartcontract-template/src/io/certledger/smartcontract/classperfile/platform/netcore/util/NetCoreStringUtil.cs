using System.Text;

namespace CertLedgerBusinessSCTemplate
{
    public class NetCoreStringUtil
    {
        public static string ByteArrayToString(byte[] data)
        {
            return Encoding.ASCII.GetString(data);
        }

        public static byte[] StringToByteArray(string text)
        {
            return Encoding.ASCII.GetBytes(text);
        }
    }
}