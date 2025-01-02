using PcapCompressor.Tools;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PcapCompressor.CompressEnv
{
    internal class ParallelIO
    {
        static object locker = new object();
        static int startCount = 0;

        static ConcurrentQueue<List<bool>>[] queues=null;

        public static void RunParallelConvertBit(string filePath, int threadCount, List<Tuple<long, int>> preReadList, ScanInfo scanInfo)
        {
            FileStream pcapfileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
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
            pcapfileStream.Close();
            queues=new ConcurrentQueue<List<bool>>[threadCount];

            List<bool> boolList = new List<bool>();

            List<Thread> threads = new List<Thread>();


            var pktlenBitCount = Tools.BitByteConvert.CountBits(scanInfo.sort_dict_PKTLength.Count);

            //Eth
            var macBitCount = Tools.BitByteConvert.CountBits(scanInfo.sort_dict_Ethernet_MAC.Count);
            var bitCount_eth_Type = Tools.BitByteConvert.CountBits(scanInfo.sort_dict_Ethernet_Type.Count);

            var protocolbitCount= Tools.BitByteConvert.CountBits(scanInfo.sort_dict_Protocol.Count);
            var ipaddrbitCount = Tools.BitByteConvert.CountBits(scanInfo.sort_dict_IPAddress.Count);

            List<bool> spanProtocol=new List<bool>();
            for(int i = 0; i<protocolbitCount; i++)
            {
                spanProtocol.Add(true);
            }
            List<bool> spanIPAddress = new List<bool>();
            for (int i = 0; i < ipaddrbitCount; i++)
            {
                spanIPAddress.Add(true);
            }

            //var ipv4addrbitCount = Tools.BitByteConvert.CountBits(scanInfo.sort_dict_IPv4_Address.Count);
            //var ipv6addrbitCount=Tools.BitByteConvert.CountBits(scanInfo.sort_dict_IPv6_Address.Count);

            //多线程读
            for (int ti = 0; ti < threadCount; ti++)
            {
                int nowti = ti;
                queues[nowti] = new ConcurrentQueue<List<bool>>();
                threads.Add(new Thread(delegate ()
                {
                    lock (locker)
                    {
                        startCount++;
                    }
                    using (FileStream fs = new(filePath, FileMode.Open, System.IO.FileAccess.Read, FileShare.ReadWrite))
                    {
                        //每个线程mod读
                        for (int i = nowti; i < preReadList.Count; i += threadCount)
                        {

                            List<bool> boolList = new List<bool>();

                            //pktlength
                            boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 8, 4, scanInfo.sort_dict_PKTLength, pktlenBitCount));

                            //maccount
                            boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 16, 12, scanInfo.sort_dict_Ethernet_MAC, macBitCount));
                            //ethtype
                            boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 28, 2, scanInfo.sort_dict_Ethernet_Type, bitCount_eth_Type));

                            var l3type = ReadFileByte(fs, preReadList[i].Item1 + 28, 2);
                            
                            //IPv4
                            if (l3type[0] == 0x8 && l3type[1] == 0x00)
                            {
                                //protocol
                                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 0x27, 1, scanInfo.sort_dict_Protocol,protocolbitCount));
                                //addr
                                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 0x2A, 4, scanInfo.sort_dict_IPAddress, ipaddrbitCount));
                                //boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 0x2A, 8, scanInfo.sort_dict_IPv4_Address, ipv4addrbitCount));
                                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 0x2E, 4, scanInfo.sort_dict_IPAddress, ipaddrbitCount));
                            }
                            //IPv6
                            else if (l3type[0] == 0x86 && l3type[1] == 0xdd)
                            {
                                //protocol
                                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 0x24, 1, scanInfo.sort_dict_Protocol, protocolbitCount));
                                //addr
                                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 0x26, 0x10, scanInfo.sort_dict_IPAddress, ipaddrbitCount));
                                //boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 0x26, 0x20, scanInfo.sort_dict_IPv6_Address, ipv6addrbitCount));
                                boolList.AddRange(Tools.BitByteConvert.GetTargetBits(fs, preReadList[i].Item1 + 0x36, 0x10, scanInfo.sort_dict_IPAddress, ipaddrbitCount));
                            }
                            //字节对齐方便多线程还原
                            else
                            {
                                boolList.AddRange(spanProtocol);
                                boolList.AddRange(spanIPAddress);
                                boolList.AddRange(spanIPAddress);
                            }
                            
                            queues[i%threadCount].Enqueue(boolList);

                        }
                    }
                    lock (locker)
                    {
                        startCount--;
                    }
                }));
                threads[ti].Start();
            }



        }

        public static byte[] ReadFileByte(FileStream pcapFileStream,long readPosition,int readLength)
        {
            pcapFileStream.Seek(readPosition, SeekOrigin.Begin);
            byte[] readBytes = new byte[readLength];
            pcapFileStream.Read(readBytes, 0, readLength);
            return readBytes;
        }

        public static List<bool> GetParallelReadAndProcessResultNext(int location)
        {

            List<bool> rtn= new List<bool>();
            bool isDequeue= queues[location].TryDequeue(out rtn);

            while (!isDequeue)
            {
                isDequeue = queues[location].TryDequeue(out rtn);
                //Thread.Sleep(1);
            }

            return rtn;
        }


        public static ConcurrentQueue<List<Header>>[] queues_header = null;

        public static List<Header> GetParallelRecoverAndProcessResultNext(int location)
        {

            List<Header> rtn = new List<Header>();
            bool isDequeue = queues_header[location].TryDequeue(out rtn);

            while (!isDequeue)
            {
                isDequeue = queues_header[location].TryDequeue(out rtn);
                //Thread.Sleep(1);
            }

            return rtn;
        }


        enum L3Mode { NotSet, IPv4, IPv6, Other };
        public static HeaderCollection ParallelReadHeaders(string compressFilePath, ScanInfo scanInfo,int threadCount)
        {
            HeaderCollection headerCollection = new HeaderCollection();
            if (Global.isSevenZipMode)
            {
                headerCollection.pcapHeader = SevenZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "PcapHeader").ToArray();
            }
            else
            {
                headerCollection.pcapHeader = ZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "PcapHeader").ToArray();
            }

            headerCollection.isLittleEndian = headerCollection.pcapHeader[0] > headerCollection.pcapHeader[1];

            var pktlenBitCount = Tools.BitByteConvert.CountBits(scanInfo.r_sort_dict_PKTLength.Count);
            var macBitCount = Tools.BitByteConvert.CountBits(scanInfo.r_sort_dict_Ethernet_MAC.Count);
            var bitCount_eth_Type = Tools.BitByteConvert.CountBits(scanInfo.r_sort_dict_Ethernet_Type.Count);
            var protocolbitCount = Tools.BitByteConvert.CountBits(scanInfo.r_sort_dict_Protocol.Count);
            var ipaddrbitCount = Tools.BitByteConvert.CountBits(scanInfo.r_sort_dict_IPAddress.Count);

            var allBitCount = pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount + 2*ipaddrbitCount;
            byte[] headerBytes;
            if (Global.isSevenZipMode)
            {
                headerBytes = SevenZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "header").ToArray();
            }
            else
            {
                headerBytes = ZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "header").ToArray();
            }


            //初始化线程
            List<Thread> threads = new List<Thread>();
            List<ParallelRecover> recovers = new List<ParallelRecover>();
            queues_header = new ConcurrentQueue<List<Header>>[threadCount];
            for (int ti=0; ti < threadCount; ti++)
            {
                queues_header[ti]=new ConcurrentQueue<List<Header>>(); 

                CompressEnv.ParallelRecover parallelRecover = new CompressEnv.ParallelRecover();
                parallelRecover.scanInfo = scanInfo;
                parallelRecover.threadNum = ti;
                parallelRecover.threadCount = threadCount;
                parallelRecover.pktlenBitCount=pktlenBitCount; ;
                parallelRecover.macBitCount=macBitCount;
                parallelRecover.bitCount_eth_Type=bitCount_eth_Type;
                parallelRecover.protocolbitCount=protocolbitCount;
                parallelRecover.ipaddrbitCount=ipaddrbitCount;
                parallelRecover.waitForProcessQueues = new ConcurrentQueue<byte[]>();

                recovers.Add(parallelRecover);
                threads.Add(new Thread(new ThreadStart(recovers[ti].DoParallelReadHeaders)));
                threads[ti].Start();

            }

            //读取到线程中，待处理
            int currentPushThread = 0;
            int pushCount = 0;
            for (long i = 0; i < headerBytes.LongLength; i+= allBitCount)
            {
                long readLength = headerBytes.Length - i > allBitCount ? allBitCount : headerBytes.Length - i;
                byte[] curBytes=new byte[readLength];
                Array.Copy(headerBytes,i, curBytes, 0, readLength);
                recovers[currentPushThread].waitForProcessQueues.Enqueue(curBytes);

                currentPushThread++;
                pushCount++;
                if (currentPushThread % threadCount == 0)
                {
                    currentPushThread = 0;
                }

                if (i % 1000000 == 0)
                {
                    System.Diagnostics.Debug.WriteLine(i);
                }
            }


            //通知所有线程文件加载完成
            for(int i = 0; i < threadCount; i++)
            {
                recovers[i].isLoadFinished = true;
            }

            //处理返回
            for(int i = 0; i < pushCount; i++)
            {
                headerCollection.headerList.AddRange(GetParallelRecoverAndProcessResultNext(i % threadCount));
            }
                


            return headerCollection;

        }

    }
}
