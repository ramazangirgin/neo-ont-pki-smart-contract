using System.Diagnostics;

namespace io.certledger.smartcontract.platform.netcore
{
    public class NetCoreLogger
    {
        public static void log(string message)
        {
            Trace.WriteLine(message);
        }
    }
}