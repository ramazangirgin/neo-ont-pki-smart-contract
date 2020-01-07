using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo
{
#if SMART_CONTRACT_TEST
    public class NeoVMTestStorageUtil
    {
        public static readonly byte[] TEST_ALL_KEY_LIST = StringUtil.StringToByteArray("TEST_ALL_KEYS");

        public static void addToTestKeyList(byte[] key)
        {
            Logger.log("Key :", key);
            byte[][] allKeys = new byte[1][];
            byte[] allKeysSerialized = Storage.Get(Storage.CurrentContext, TEST_ALL_KEY_LIST);
            if (allKeysSerialized == null)
            {
                allKeys = new byte[1][];
            }
            else
            {
                allKeys = (byte[][]) SerializationUtil.Deserialize(allKeysSerialized);
            }
            
            byte[][] newAllKeys = new byte[allKeys.Length + 1][];
            newAllKeys[0] = key;
            for (int i = 0; i < allKeys.Length; i++)
            {
                newAllKeys[i + 1] = allKeys[i];
            }

            byte[] newAllKeysSerialized = SerializationUtil.Serialize(newAllKeys);
            Storage.Put(Storage.CurrentContext, TEST_ALL_KEY_LIST, newAllKeysSerialized);
        }

        public static byte[][] retrieveAllKeys()
        {
            byte[] allKeysSerialized = Storage.Get(Storage.CurrentContext, TEST_ALL_KEY_LIST);
            if (allKeysSerialized != null)
            {
                return (byte[][]) SerializationUtil.Deserialize(allKeysSerialized);
            }

            return null;
        }
    }
#endif

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
#if SMART_CONTRACT_TEST
            NeoVMTestStorageUtil.addToTestKeyList(key);
#endif
        }

        public static void saveToStorage(string key, byte[] value)
        {
            Storage.Put(Storage.CurrentContext, key, value);
#if SMART_CONTRACT_TEST
            NeoVMTestStorageUtil.addToTestKeyList(key.AsByteArray());
#endif
        }

        public static void clearStorage()
        {
#if SMART_CONTRACT_TEST
            byte[][] allKeys = NeoVMTestStorageUtil.retrieveAllKeys();
            foreach (byte[] key in allKeys)
            {
                Storage.Delete(Storage.CurrentContext, key);
            }
#endif
        }
    }
}