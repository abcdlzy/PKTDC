using PcapCompressor.CompressEnv;
using SharpPcap.LibPcap;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.Exp
{
    internal class Compare
    {
        public static void SaveHeadersToFile(string pcapFilePath, string extractFilePath)
        {
            FileStream pcapfileStream = new FileStream(pcapFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            FileStream fileStream = new FileStream(extractFilePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
            BinaryWriter binaryWriter = new BinaryWriter(fileStream);

            byte[] pcapheader = new byte[24];
            pcapfileStream.Read(pcapheader, 0, 24);

            bool isLittleEndian = pcapheader[0] > pcapheader[1];

            byte[] linktype = new byte[4];
            if (isLittleEndian)
            {
                linktype = Tools.EndianCovert.ReadLittle(pcapheader, 20, 4);
            }
            else
            {
                linktype = Tools.EndianCovert.ReadBig(pcapheader, 20, 4);
            }

            //只处理以太网
            /*
            if (BitConverter.ToInt32(linktype, 0) != 1)
            {
                new NotImplementedException();
                return;
            }
            */

            int pktCount = 0;
            long startposition = 24;
            int position = 0;
            byte[] currentPktLen = new byte[4];
            int currentIntPktLen = 0;
            pcapfileStream.Seek(startposition + 8, SeekOrigin.Begin);

            while (pcapfileStream.Read(currentPktLen, 0, 4) != 0)
            {

                if (isLittleEndian)
                {
                    currentIntPktLen = Tools.EndianCovert.LittleToInt(currentPktLen);
                }
                else
                {
                    currentIntPktLen = Tools.EndianCovert.BigToInt(currentPktLen);
                }
                /*
                pcapfileStream.Seek(startposition, SeekOrigin.Begin);
                byte[] readBytes1 = new byte[4];
                pcapfileStream.Read(readBytes1, 0, 4);
                binaryWriter.Write(readBytes1);
                */
                pcapfileStream.Seek(startposition + 8, SeekOrigin.Begin);
                byte[] readBytes = new byte[22];
                pcapfileStream.Read(readBytes, 0, 22);
                binaryWriter.Write(readBytes);

                startposition += currentIntPktLen + 16;
                pcapfileStream.Seek(startposition + 8, SeekOrigin.Begin);

            }
            binaryWriter.Close();
            fileStream.Close();
            pcapfileStream.Close();
        }


        public static void DoubleCompressSaveHeadersToFile(string pcapFilePath, string extractFilePath)
        {
            FileStream pcapfileStream = new FileStream(pcapFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            FileStream fileStream = new FileStream(extractFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            BinaryWriter binaryWriter = new BinaryWriter(fileStream);

            byte[] pcapheader = new byte[24];
            pcapfileStream.Read(pcapheader, 0, 24);

            bool isLittleEndian = pcapheader[0] > pcapheader[1];

            byte[] linktype = new byte[4];
            if (isLittleEndian)
            {
                linktype = Tools.EndianCovert.ReadLittle(pcapheader, 20, 4);
            }
            else
            {
                linktype = Tools.EndianCovert.ReadBig(pcapheader, 20, 4);
            }

            //只处理以太网
            /*
            if (BitConverter.ToInt32(linktype, 0) != 1)
            {
                new NotImplementedException();
                return;
            }
            */

            int pktCount = 0;
            long startposition = 24;
            int position = 0;
            byte[] currentPktLen = new byte[4];
            int currentIntPktLen = 0;
            pcapfileStream.Seek(startposition + 8, SeekOrigin.Begin);

            //缓存基础信息
            //Pcap
            PcapParser.scanInfo.sort_dict_PKTLength = PcapParser.scanInfo.dict_PKTLength.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            var pktlenBitCount = Tools.BitByteConvert.CountBits(PcapParser.scanInfo.sort_dict_PKTLength.Count);

            //Eth
            PcapParser.scanInfo.sort_dict_Ethernet_MAC = PcapParser.scanInfo.dict_Ethernet_MAC.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            var macBitCount = Tools.BitByteConvert.CountBits(PcapParser.scanInfo.sort_dict_Ethernet_MAC.Count);

            PcapParser.scanInfo.sort_dict_Ethernet_Type = PcapParser.scanInfo.dict_Ethernet_Type.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            var bitCount_eth_Type = Tools.BitByteConvert.CountBits(PcapParser.scanInfo.sort_dict_Ethernet_Type.Count);


            List<bool> boolList = new List<bool>();
            while (pcapfileStream.Read(currentPktLen, 0, 4) != 0)
            {
                if (isLittleEndian)
                {
                    currentIntPktLen = Tools.EndianCovert.LittleToInt(currentPktLen);
                }
                else
                {
                    currentIntPktLen = Tools.EndianCovert.BigToInt(currentPktLen);
                }

                //pktlength
                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(pcapfileStream, startposition + 8, 4, PcapParser.scanInfo.sort_dict_PKTLength, pktlenBitCount));

                //maccount
                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(pcapfileStream, startposition + 16, 12, PcapParser.scanInfo.sort_dict_Ethernet_MAC, macBitCount));
                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(pcapfileStream, startposition + 28, 2, PcapParser.scanInfo.sort_dict_Ethernet_Type, bitCount_eth_Type));




                startposition += currentIntPktLen + 16;
                pcapfileStream.Seek(startposition + 8, SeekOrigin.Begin);

                //减少内存压力
                if (boolList.Count == 8 * 1000000)
                {
                    System.Diagnostics.Debug.WriteLine(startposition);
                    bool[] newBoolArr = boolList.ToArray();
                    var writeArray = Tools.BitByteConvert.BitArrayToByteArray(newBoolArr);
                    // 将新的 bool 数组写入文件
                    fileStream.Write(writeArray, 0, writeArray.Length);
                    boolList.Clear();

                }

            }

            bool[] newBoolArr1 = boolList.ToArray();
            var writeArray1 = Tools.BitByteConvert.BitArrayToByteArray(newBoolArr1);
            // 将新的 bool 数组写入文件
            fileStream.Write(writeArray1, 0, writeArray1.Length);

            binaryWriter.Close();
            fileStream.Close();
            pcapfileStream.Close();
        }


        public static void MultiThreadDoubleCompressSaveHeadersToFile(string pcapFilePath, string extractFilePath, List<Tuple<long, int>> preReadList, ScanInfo scanInfo)
        {

            int threadCount = Global.thread_ConvertCount;
            ParallelIO.RunParallelConvertBit(pcapFilePath, threadCount, preReadList, scanInfo);
            List<bool> boolList = new List<bool>();

            using (FileStream fileStream = new FileStream(extractFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
            {
                System.Diagnostics.Debug.WriteLine("start write file");
                for (int i = 0; i < preReadList.Count; i++)
                {

                    boolList.AddRange(ParallelIO.GetParallelReadAndProcessResultNext(i % threadCount));

                    if (boolList.Count > 8 * 1000000)
                    {
                        System.Diagnostics.Debug.WriteLine(i);
                        bool[] newBoolArr = boolList.Take(8 * 1000000).ToArray();
                        boolList.RemoveRange(0, 8 * 1000000);
                        var writeArray = Tools.BitByteConvert.BitArrayToByteArray(newBoolArr);
                        // 将新的 bool 数组写入文件
                        fileStream.Write(writeArray, 0, writeArray.Length);
                        fileStream.Flush();
                    }
                }
                System.Diagnostics.Debug.WriteLine("end  write file");
                fileStream.Flush();
                fileStream.Close();
            }


        }

    }
}
