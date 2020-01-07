using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using Helper = Neo.SmartContract.Framework.Helper;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo
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

    public class NeoVMStringUtil
    {
        public static string ByteArrayToString(byte[] data)
        {
            return data.AsString();
        }

        public static byte[] StringToByteArray(string text)
        {
            return text.AsByteArray();
        }
    }

    public class NeoVMTransactionUtil
    {
        public static long retrieveTransactionTime()
        {
            Header header = Blockchain.GetHeader(Blockchain.GetHeight());
            return header.Timestamp;
        }
    }
}