#if NEO
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo;

#endif
#if NET_CORE
using io.certledger.smartcontract.platform.netcore;
#endif

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class StorageUtil
    {
        public static byte[] readFromStorage(string key)
        {
#if NET_CORE
                            return NetCoreStorageUtil.readFromStorage(key);
#endif
#if NEO
            return NeoVMStorageUtil.readFromStorage(key);
#endif
        }

        public static byte[] readFromStorage(byte[] key)
        {
#if NET_CORE
                            return NetCoreStorageUtil.readFromStorage(key);
#endif
#if NEO
            return NeoVMStorageUtil.readFromStorage(key);
#endif
        }

        public static void saveToStorage(byte[] key, byte[] value)
        {
#if NET_CORE
                            NetCoreStorageUtil.saveToStorage(key, value);
#endif
#if NEO
            NeoVMStorageUtil.saveToStorage(key, value);
#endif
        }

        public static void saveToStorage(string key, byte[] value)
        {
#if NET_CORE
                            NetCoreStorageUtil.saveToStorage(key, value);
#endif
#if NEO
            NeoVMStorageUtil.saveToStorage(key, value);
#endif
        }

        //todo: testing purposes only. Not used in real smart contract
        public static void clearStorage()
        {
#if NET_CORE
                            NetCoreStorageUtil.clearStorage();
#endif
#if NEO
            NeoVMStorageUtil.clearStorage();
#endif
        }
    }
}