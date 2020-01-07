using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using Helper = Neo.SmartContract.Framework.Helper;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo
{
    public class NeoVMLogger
    {
        public static void log(string fieldName, object value)
        {
#if SMART_CONTRACT_TEST
            Runtime.Notify(fieldName);
            Runtime.Notify(value);
#endif
        }

        public static void log(string message, byte[] argument)
        {
#if SMART_CONTRACT_TEST
            Runtime.Notify(Helper.Concat(message.AsByteArray(), argument));
            Runtime.Notify(argument);
#endif
        }

        public static void log(object message)
        {
#if SMART_CONTRACT_TEST
            Runtime.Notify(message);
#endif
        }

        public static void log(bool message)
        {
#if SMART_CONTRACT_TEST
            if (message)
            {
                Runtime.Notify("true");
            }
            else
            {
                Runtime.Notify("false");
            }
#endif
        }

        public static void log(string condition, bool status)
        {
#if SMART_CONTRACT_TEST
            if (status)
            {
                Runtime.Notify(Helper.Concat(condition.AsByteArray(), "true".AsByteArray()));
            }
            else
            {
                Runtime.Notify(Helper.Concat(condition.AsByteArray(), "false".AsByteArray()));
            }
#endif
        }
    }
}