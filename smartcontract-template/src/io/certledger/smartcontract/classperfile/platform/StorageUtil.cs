namespace io.certledger.smartcontract.business.util
{
    public class StorageUtil
    {
        public static byte[] readFromStorage(string key)
        {
            //return NeoVMStorageUtil.readFromStorage(key);
            return NetCoreStorageUtil.readFromStorage(key);
        }

        public static byte[] readFromStorage(byte[] key)
        {
            //return NeoVMStorageUtil.readFromStorage(key);
            return NetCoreStorageUtil.readFromStorage(key);
        }

        public static void saveToStorage(byte[] key, byte[] value)
        {
            //NeoVMStorageUtil.saveToStorage(key,value);
            NetCoreStorageUtil.saveToStorage(key,value);
        }

        public static void saveToStorage(string key, byte[] value)
        {
            //NeoVMStorageUtil.saveToStorage(key,value);
            NetCoreStorageUtil.saveToStorage(key,value);
        }
        
        //todo: testing purposes only. Not used in real smart contract
        public static void clearStorage()
        {
            NetCoreStorageUtil.clearStorage();
            
        }
    }
}