namespace io.certledger.smartcontract.business.util
{
    public class SerializationUtil
    {
        public static byte[] Serialize(object source)
        {
            return NetCoreSerializationUtil.Serialize(source);
        }

        public static object Deserialize(byte[] source)
        {
            return NetCoreSerializationUtil.Deserialize(source);
        }
    }
}