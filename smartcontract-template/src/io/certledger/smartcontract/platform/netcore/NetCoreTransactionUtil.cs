using System;

namespace io.certledger.smartcontract.platform.netcore
{
    public class NetCoreTransactionUtil
    {
        public static long retrieveTransactionTime()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }
    }
}