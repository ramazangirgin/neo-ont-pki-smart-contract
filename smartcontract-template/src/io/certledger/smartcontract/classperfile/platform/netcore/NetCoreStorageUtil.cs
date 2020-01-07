using System.Collections.Generic;

namespace io.certledger.smartcontract.business.util
{
    public class NetCoreStorageUtil
    {
        public static Dictionary<byte[], byte[]> storageMap = new Dictionary<byte[], byte[]>(new ByteArrayComparer());

        public static byte[] readFromStorage(string key)
        {
            return readFromStorage(StringUtil.StringToByteArray(key));
        }

        public static byte[] readFromStorage(byte[] key)
        {
            if (storageMap.ContainsKey(key))
            {
                return storageMap[key];
            }
            else
            {
                return null;
            }
        }

        public static void saveToStorage(byte[] key, byte[] value)
        {
            storageMap[key] = value;
        }

        public static void saveToStorage(string key, byte[] value)
        {
            saveToStorage(StringUtil.StringToByteArray(key), value);
        }

        public static void clearStorage()
        {
            storageMap.Clear();
        }
    }
}