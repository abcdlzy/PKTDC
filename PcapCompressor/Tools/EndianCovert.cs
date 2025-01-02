using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.Tools
{
    internal class EndianCovert
    {

        public static byte[] ReadLittle(byte[] source,int start,int len)
        {

            var revertByteList = new byte[len];
            Array.Copy(source, start, revertByteList, 0, len);
            return revertByteList;
        }

        public static int ReadLittleToInt(byte[] source, int start, int len)
        {

            var revertByteList = new byte[len];
            Array.Copy(source, start, revertByteList, 0, len);
            return BitConverter.ToInt32(revertByteList, 0);

        }

        public static int LittleToInt(byte[] source)
        {
            return BitConverter.ToInt32(source, 0);
        }


        public static byte[] ReadBig(byte[] source, int start, int len)
        {

            var revertByteList = new byte[len];
            Array.Copy(source, start, revertByteList, 0, len);
            revertByteList = revertByteList.Reverse().ToArray();
            return revertByteList;

        }

        public static int ReadBigToInt(byte[] source, int start, int len)
        {

            var revertByteList = new byte[len];
            Array.Copy(source, start, revertByteList, 0, len);
            revertByteList = revertByteList.Reverse().ToArray();
            return BitConverter.ToInt32(revertByteList, 0);

        }

        public static int BigToInt(byte[] source)
        {
            return BitConverter.ToInt32(source.Reverse().ToArray(), 0);
        }
    }
}
