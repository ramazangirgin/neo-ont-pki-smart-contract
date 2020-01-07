#if NEO
using Neo.SmartContract.Framework;

#endif
#if NET_CORE
using io.certledger.smartcontract.platform.netcore;
#endif
namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public class Constants
    {    
#if NEO
        public static readonly byte[] ALG_NAME_RSA_UPPERCASE = "525341".HexToBytes();
        public static readonly byte[] ALG_NAME_RSA_LOWERCASE = "727361".HexToBytes();
        public static readonly byte[] ALG_NAME_EC_UPPERCASE = "4543".HexToBytes();
        public static readonly byte[] ALG_NAME_EC_LOWERCASE = "6563".HexToBytes();
        
        public static readonly byte[] EXTENDED_KEY_USAGE_OID_SERVER_AUTHENTICATION = "312e332e362e312e352e352e372e332e31".HexToBytes();
        public static readonly byte[] EXTENDED_KEY_OID_USAGE_CLIENT_AUTHENTICATION = "312e332e362e312e352e352e372e332e32".HexToBytes();
        public static readonly byte[] EXTENDED_KEY_OID_EMAIL_PROTECTION = "312e332e362e312e352e352e372e332e34".HexToBytes();
#endif
#if NET_CORE
        public static readonly byte[] ALG_NAME_RSA_UPPERCASE = HexUtil.HexStringToByteArray("525341");
        public static readonly byte[] ALG_NAME_RSA_LOWERCASE = HexUtil.HexStringToByteArray("727361");
        public static readonly byte[] ALG_NAME_EC_UPPERCASE = HexUtil.HexStringToByteArray("4543");
        public static readonly byte[] ALG_NAME_EC_LOWERCASE = HexUtil.HexStringToByteArray("6563");
    
        public static readonly byte[] EXTENDED_KEY_USAGE_OID_SERVER_AUTHENTICATION = HexUtil.HexStringToByteArray("312e332e362e312e352e352e372e332e31");
        public static readonly byte[] EXTENDED_KEY_OID_USAGE_CLIENT_AUTHENTICATION = HexUtil.HexStringToByteArray("312e332e362e312e352e352e372e332e32");
        public static readonly byte[] EXTENDED_KEY_OID_EMAIL_PROTECTION = HexUtil.HexStringToByteArray("312e332e362e312e352e352e372e332e34");
#endif
    }
}