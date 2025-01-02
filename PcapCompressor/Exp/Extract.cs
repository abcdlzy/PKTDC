using PcapCompressor.CompressEnv;
using PcapCompressor.Tools;
using SharpPcap.LibPcap;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.Exp
{
    internal static class Extract
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
                byte[] readBytes_pktlen = new byte[4];
                byte[] readBytes_mac = new byte[16];
                byte[] readBytes_l3type = new byte[2];
                byte[] readBytes_protocol = new byte[1];
                byte[] readBytes_ipv4_src = new byte[4];
                byte[] readBytes_ipv4_dst = new byte[4];
                byte[] readBytes_ipv6_src = new byte[0x10];
                byte[] readBytes_ipv6_dst = new byte[0x10];
                

                pcapfileStream.Seek(startposition + 8, SeekOrigin.Begin);
                pcapfileStream.Read(readBytes_pktlen, 0, 4);
                pcapfileStream.Seek(startposition + 16, SeekOrigin.Begin);
                pcapfileStream.Read(readBytes_mac, 0, 16);
                pcapfileStream.Seek(startposition + 28, SeekOrigin.Begin);
                pcapfileStream.Read(readBytes_l3type, 0, 2);
                if (readBytes_l3type[0] == 0x8 && readBytes_l3type[1] == 0x00)
                {
                    pcapfileStream.Seek(startposition + 0x27, SeekOrigin.Begin);
                    pcapfileStream.Read(readBytes_protocol, 0, 1);
                    pcapfileStream.Seek(startposition + 0x2A, SeekOrigin.Begin);
                    pcapfileStream.Read(readBytes_ipv4_src, 0, 4);
                    pcapfileStream.Seek(startposition + 0x2E, SeekOrigin.Begin);
                    pcapfileStream.Read(readBytes_ipv4_dst, 0, 4);

                    byte[] readBytes = new byte[31];
                    Array.Copy(readBytes_pktlen, 0, readBytes, 0, 4);
                    Array.Copy(readBytes_mac, 0, readBytes, 4, 16);
                    Array.Copy(readBytes_l3type, 0, readBytes, 20, 2);
                    Array.Copy(readBytes_protocol, 0, readBytes, 22, 1);
                    Array.Copy(readBytes_ipv4_src, 0, readBytes, 23, 4);
                    Array.Copy(readBytes_ipv4_dst, 0, readBytes, 27, 4);
                    binaryWriter.Write(readBytes);
                }
                else if (readBytes_l3type[0] == 0x86 && readBytes_l3type[1] == 0xdd)
                {
                    pcapfileStream.Seek(startposition + 0x24, SeekOrigin.Begin);
                    pcapfileStream.Read(readBytes_protocol, 0, 1);
                    pcapfileStream.Seek(startposition + 0x26, SeekOrigin.Begin);
                    pcapfileStream.Read(readBytes_ipv6_src, 0, 0x10);
                    pcapfileStream.Seek(startposition + 0x36, SeekOrigin.Begin);
                    pcapfileStream.Read(readBytes_ipv6_dst, 0, 0x10);

                    byte[] readBytes = new byte[55];
                    Array.Copy(readBytes_pktlen, 0, readBytes, 0, 4);
                    Array.Copy(readBytes_mac, 0, readBytes, 4, 16);
                    Array.Copy(readBytes_l3type, 0, readBytes, 20, 2);
                    Array.Copy(readBytes_protocol, 0, readBytes, 22, 1);
                    Array.Copy(readBytes_ipv6_src, 0, readBytes, 23, 16);
                    Array.Copy(readBytes_ipv6_dst, 0, readBytes, 39, 16);
                    binaryWriter.Write(readBytes);
                }
                else
                {
                    byte[] readBytes = new byte[22];
                    Array.Copy(readBytes_pktlen,0,readBytes, 0, 4);
                    Array.Copy(readBytes_mac, 0, readBytes, 4, 16);
                    Array.Copy(readBytes_l3type, 0, readBytes, 20, 2);
                    binaryWriter.Write(readBytes);
                }


                startposition += currentIntPktLen + 16;
                pcapfileStream.Seek(startposition + 8, SeekOrigin.Begin);

            }
            binaryWriter.Close();
            fileStream.Close();
            pcapfileStream.Close();
        }


        public static void DoubleCompressSaveHeadersToFile(string pcapFilePath, string extractFilePath)
        {
            new NotImplementedException();
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
            /*
            var sort_TimeSec = PcapParser.scanInfo.TimeSecCount.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            var bitCount_TimeSec = Tools.BitByteConvert.CountBits(sort_TimeSec.Count);

            var sort_TimeMSec = PcapParser.scanInfo.TimeMSecCount.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            var bitCount_TimeMSec = Tools.BitByteConvert.CountBits(sort_TimeMSec.Count);

            var sort_TotalLength = PcapParser.scanInfo.TotalLengthCount.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            var bitCount_TotalLength = Tools.BitByteConvert.CountBits(sort_TotalLength.Count);
           
            var pktlensort = PcapParser.scanInfo.PKTLengthCount.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            var pktlenBitCount = Tools.BitByteConvert.CountBits(pktlensort.Count);

            //Eth
            var macsort = PcapParser.scanInfo.Ethernet_MACCount.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            var macBitCount = Tools.BitByteConvert.CountBits(macsort.Count);

            var sort_eth_Type = PcapParser.scanInfo.Ethernet_TypeCount.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            var bitCount_eth_Type = Tools.BitByteConvert.CountBits(sort_eth_Type.Count);
           

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
                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(pcapfileStream, startposition + 8, 4, pktlensort, pktlenBitCount));

                //maccount
                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(pcapfileStream, startposition + 16, 12, macsort, macBitCount));
                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(pcapfileStream, startposition + 28, 2, sort_eth_Type, bitCount_eth_Type));
          



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
                */
            binaryWriter.Close();
            fileStream.Close();
            pcapfileStream.Close();
        }


        public static void MultiThreadDoubleCompressSaveHeadersToFile(string pcapFilePath, string extractFilePath, List<Tuple<long, int>> preReadList, ScanInfo scanInfo)
        {

            int threadCount = Global.thread_ConvertCount;
            ParallelIO.RunParallelConvertBit(pcapFilePath, threadCount, preReadList, scanInfo);
            List<bool> boolList = new List<bool>();

            var memorystream = new HugeMemoryStream();
            
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
                    memorystream.Write(writeArray, 0, writeArray.Length);
                }
            }


            bool[] newBoolArr1 = boolList.ToArray();
            var writeArray1 = Tools.BitByteConvert.BitArrayToByteArray(newBoolArr1);
            // 将新的 bool 数组写入文件
            memorystream.Write(writeArray1, 0, writeArray1.Length);
            if (Global.isSevenZipMode)
            {
                SevenZipArchiveHelper.AddToZipArchive(extractFilePath, "header", memorystream);
            }
            else
            {
                ZipArchiveHelper.AddToZipArchive(extractFilePath, "header", memorystream);
            }

            
            System.Diagnostics.Debug.WriteLine("end  write file");

        }

        public static void SaveDictionaryToZipArchive(string zipFilePath,ScanInfo scanInfo)
        {
            if (Global.isSevenZipMode)
            {
                SevenZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-pktLen", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_PKTLength));
                SevenZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-MAC", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_Ethernet_MAC));
                SevenZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-type", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_Ethernet_Type));

                SevenZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-protocol", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_Protocol));
                SevenZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-IPAddress", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_IPAddress));
            }
            else
            {
                ZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-pktLen", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_PKTLength));
                ZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-MAC", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_Ethernet_MAC));
                ZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-type", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_Ethernet_Type));

                ZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-protocol", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_Protocol));
                ZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-IPAddress", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_IPAddress));
                //ZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-IPv4Address", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_IPv4_Address));
                //ZipArchiveHelper.AddToZipArchive(zipFilePath, "dict-IPv6Address", Serialization.SerializeConcurrentDictionary(scanInfo.sort_dict_IPv6_Address));
            }

        }

        public static void SavePayloadToZipArchive(string pcapFilePath,string zipFilePath, List<Tuple<long, int>> preReadList)
        {

            #region save pcap header
            FileStream pcapfileStream = new FileStream(pcapFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

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
            if (Global.isSevenZipMode)
            {
                SevenZipArchiveHelper.AddToZipArchive(zipFilePath, "PcapHeader", new HugeMemoryStream(pcapheader));
            }
            else
            {

                ZipArchiveHelper.AddToZipArchive(zipFilePath, "PcapHeader", pcapheader);
            }

            pcapfileStream.Close();
            #endregion
            //初始化线程环境
            List<Thread> threads = new List<Thread>();
            List<ParallelSavePayload> parallelSavePayloads = new List<ParallelSavePayload>();
            int blocksCount = preReadList.Count / Global.splitCount;
            //将需要处理的块编号放置入线程并启动
            for (int ti = 0; ti < Global.thread_ConvertCount; ti++)
            {
                CompressEnv.ParallelSavePayload parallelSavePayload = new CompressEnv.ParallelSavePayload();
                parallelSavePayload.zipFilePath = zipFilePath;
                parallelSavePayload.filePath = pcapFilePath;
                parallelSavePayload.preReadList = preReadList;

                //计算需要处理的块
                for(int i=ti;i< blocksCount+1; i+= Global.thread_ConvertCount)
                {
                    parallelSavePayload.taskBlock.Add(i);
                }

                parallelSavePayloads.Add(parallelSavePayload);
                threads.Add(new Thread(new ThreadStart(parallelSavePayloads[ti].DoParallelSavePayload)));
                threads[ti].Start();
            }



            #region final save to file
            do{
                Thread.Sleep(100);
            } while (ParallelSavePayload.startCount > 0) ;
                if (Global.isSevenZipMode)
            {
                SevenZipArchiveHelper.DoCompressToZipArchive(zipFilePath);
            }

            #endregion
        }

        public static byte[] Compress(byte[] data)
        {
            using (HugeMemoryStream output = new HugeMemoryStream())
            {
                using (DeflateStream deflate = new DeflateStream(output, CompressionMode.Compress))
                {
                    deflate.Write(data, 0, data.Length);
                }
                return output.ToArray();
            }
        }
    }
}
