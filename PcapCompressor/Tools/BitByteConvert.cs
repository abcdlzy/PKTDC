using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.Tools
{
    internal class BitByteConvert
    {
        public static bool[] IntToBits(int num, int bitCount)
        {
            bool[] bits = new bool[bitCount];
            for (int i = 0; i < bitCount; i++)
            {
                bits[i] = (num & (1 << (bitCount - i - 1))) != 0;
            }
            return bits;
        }

        public static int BitsToInt(bool[] bits)
        {
            int num = 0;
            for (int i = 0; i < bits.Length; i++)
            {
                if (bits[i])
                {
                    num |= (1 << (bits.Length - i - 1));
                }
            }
            return num;
        }

        public static bool[] ByteToBits(byte b)
        {
            bool[] bits = new bool[8];
            for (int i = 0; i < 8; i++)
            {
                bits[i] = (b & (1 << (7 - i))) != 0;
            }
            return bits;
        }

        public static byte[] BoolArrayToByteArray(bool[] boolArray)
        {
            int byteLength = (boolArray.Length + 7) / 8;
            byte[] byteArray = new byte[byteLength];

            for (int i = 0; i < boolArray.Length; i++)
            {
                int byteIndex = i / 8;
                int bitIndex = i % 8;

                if (boolArray[i])
                {
                    byteArray[byteIndex] |= (byte)(1 << bitIndex);
                }
            }

            return byteArray;
        }

        public static bool[] ConcatenateBoolArrays(bool[] array1, bool[] array2)
        {
            bool[] result = new bool[array1.Length + array2.Length];
            Array.Copy(array1, 0, result, 0, array1.Length);
            Array.Copy(array2, 0, result, array1.Length, array2.Length);
            return result;
        }

        public static int CountBits(int number)
        {
            int count = 0;
            while (number > 0)
            {
                count++;
                number >>= 1;
            }
            return count;
        }

        public static byte[] BitArrayToByteArray(bool[] bits)
        {
            int numBytes = bits.Length / 8;
            if (bits.Length % 8 != 0) numBytes++;

            byte[] bytes = new byte[numBytes];
            int byteIndex = 0, bitIndex = 0;

            for (int i = 0; i < bits.Length; i++)
            {
                if (bits[i]) bytes[byteIndex] |= (byte)(1 << (7 - bitIndex));

                bitIndex++;
                if (bitIndex == 8)
                {
                    bitIndex = 0;
                    byteIndex++;
                }
            }

            return bytes;
        }

        public static bool[] GetTargetBits(FileStream pcapFileStream, long readPosition, int readLength, Dictionary<byte[], int> sortDictionary, int bitLength)
        {
            pcapFileStream.Seek(readPosition, SeekOrigin.Begin);
            byte[] readBytes = new byte[readLength];
            pcapFileStream.Read(readBytes, 0, readLength);
            var findMACLoc = FindKeyIndex(sortDictionary, readBytes);

                
            return Tools.BitByteConvert.IntToBits(findMACLoc, bitLength);
        }

        public static int FindKeyIndex(Dictionary<byte[], int> dictionary, byte[] key)
        {
            return dictionary[key];
        }



        /*
        public static int FindKeyIndex(Dictionary<byte[], int> dictionary, byte[] key)
        {
            var iterator = dictionary.GetEnumerator();
            int index = 0;

            while (iterator.MoveNext())
            {
                if (StructuralComparisons.StructuralEqualityComparer.Equals(iterator.Current.Key, key))
                {
                    return index;
                }

                index++;
            }

            return -1;
        }
        */


    }
}
