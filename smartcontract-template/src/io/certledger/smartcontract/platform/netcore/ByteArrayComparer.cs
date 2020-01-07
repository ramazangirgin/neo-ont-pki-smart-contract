using System;
using System.Collections.Generic;
using System.Linq;

namespace io.certledger.smartcontract.platform.netcore
{
    internal class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[] x, byte[] y)
        {
            if (x == null || y == null)
            {
                return x == y;
            }

            return x.SequenceEqual(y);
        }

        public int GetHashCode(byte[] obj)
        {
            return BitConverter.ToString(obj).GetHashCode();
        }
    }
}