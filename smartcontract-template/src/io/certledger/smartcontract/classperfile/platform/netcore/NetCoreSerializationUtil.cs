using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace io.certledger.smartcontract.business.util
{
    public class NetCoreSerializationUtil
    {
        public static byte[] Serialize(object source)
        {
            using (var stream = new MemoryStream())
            {
                var formatter = new BinaryFormatter();

                formatter.Serialize(stream, source);

                return stream.ToArray();
            }
        }

        public static object Deserialize(byte[] source)
        {
            using (var stream = new MemoryStream(source))
            {
                var formatter = new BinaryFormatter();

                return formatter.Deserialize(stream);
            }
        }
    }
}