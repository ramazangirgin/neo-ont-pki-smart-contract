#if NEO
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo;

#endif

#if NET_CORE
using io.certledger.smartcontract.platform.netcore;
#endif

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class SerializationUtil
    {
        public static byte[] Serialize(object source)
        {
#if NET_CORE
                            return NetCoreSerializationUtil.Serialize(source);
#endif
#if NEO
            return NeoVMSerializationUtil.Serialize(source);
#endif
        }

        public static object Deserialize(byte[] source)
        {
#if NET_CORE
                            return NetCoreSerializationUtil.Deserialize(source);
#endif
#if NEO
            return NeoVMSerializationUtil.Deserialize(source);
#endif
        }
    }

    public class ArrayUtil
    {
        public static byte[] Concat(byte[] first, byte[] second)
        {
#if NET_CORE
                            return NetCoreArrayUtil.concat(first, second);
#endif
#if NEO
            return NeoVMArrayUtil.concat(first, second);
#endif
        }

        public static bool Contains(byte[] source, byte[] find)
        {
            for (int i = 0, index = 0; i < source.Length; ++i)
            {
                if (source[i] == find[index])
                {
                    if (++index >= find.Length)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool AreEqual(byte[] first, byte[] second)
        {
#if NET_CORE
                            return NetCoreArrayUtil.AreEqual(first, second);
#endif
#if NEO
            return NeoVMArrayUtil.AreEqual(first, second);
#endif
        }
    }

    public class StringUtil
    {
        public static string ByteArrayToString(byte[] data)
        {
#if NEO
            return NeoVMStringUtil.ByteArrayToString(data);
#endif
#if NET_CORE
                            return NetCoreStringUtil.ByteArrayToString(data);
#endif
        }

        public static byte[] StringToByteArray(string text)
        {
#if NEO
            return NeoVMStringUtil.StringToByteArray(text);
#endif
#if NET_CORE
                            return NetCoreStringUtil.StringToByteArray(text);
#endif
        }
    }

    public class TransactionContentUtil
    {
        public static long retrieveTransactionTime()
        {
#if NEO
            return NeoVMTransactionUtil.retrieveTransactionTime();
#endif
#if NET_CORE
                            return NetCoreTransactionUtil.retrieveTransactionTime();
#endif
        }
    }
}