using Neo.SmartContract.Framework.Services.Neo;

namespace io.certledger.smartcontract.business.util
{
    public class NeoVMStorageUtil
    {
        public static byte[] readFromStorage(string key)
        {
            return Storage.Get(Storage.CurrentContext, key);
        }

        public static byte[] readFromStorage(byte[] key)
        {
            return Storage.Get(Storage.CurrentContext, key);
        }

        public static void saveToStorage(byte[] key, byte[] value)
        {
            Storage.Put(Storage.CurrentContext, key, value);
        }

        public static void saveToStorage(string key, byte[] value)
        {
            Storage.Put(Storage.CurrentContext, key, value);
        }
    }
}