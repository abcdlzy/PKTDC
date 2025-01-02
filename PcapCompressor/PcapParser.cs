using PacketDotNet;
using PcapCompressor.CompressEnv;
using PcapCompressor.Tools;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace PcapCompressor
{
    internal class PcapParser
    {
        public static ScanInfo scanInfo=new ScanInfo();

        /// <summary>
        /// 读取所有包位置，方便并行处理
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns>list of each packet (start position,length)</returns>
        public static List<Tuple<long, int>> PreRead(string filePath)
        {
            FileStream fileStream = new FileStream(filePath, FileMode.Open,FileAccess.ReadWrite,FileShare.ReadWrite);
            List<Tuple<long, int>> rtn = new List<Tuple<long, int>>();

            byte[] pcapheader=new byte[24];
            fileStream.Read(pcapheader, 0, 24);

            bool isLittleEndian = pcapheader[0] > pcapheader[1];
            //bool isLittleEndian = true;

            byte[] linktype = new byte[4];
            if(isLittleEndian)
            {
                linktype = Tools.EndianCovert.ReadLittle(pcapheader, 20, 4);
            }
            else
            {
                linktype= Tools.EndianCovert.ReadBig(pcapheader, 20, 4);
            }

            //只处理以太网
            /*
            if (BitConverter.ToInt32(linktype, 0)!=1)
            {
                new NotImplementedException();
                return rtn;
            }
            */
            //pcap Header length=24
            //Packer Header:
            /*
             *  Timestamp（4B）： 时间戳高位，精确到 seconds，这是 Unix 时间戳。捕获数据包的时间一般是根据这个值
                Timestamp（4B）： 时间戳低位，能够精确到 microseconds
                Caplen（4B）： 当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。
                Len（4B）： 离线数据长度，网路中实际数据帧的长度，一般不大于 Caplen，多数情况下和 Caplen值一样

             */
            int pktCount = 0;
            long startposition = 24;
            int position = 0;
            byte[] currentPktLen = new byte[4];
            int currentIntPktLen = 0;
            fileStream.Seek(startposition+8, SeekOrigin.Begin);

            while (fileStream.Read(currentPktLen, 0,4) !=0)
            {

                if (isLittleEndian)
                {
                    currentIntPktLen = Tools.EndianCovert.LittleToInt(currentPktLen);
                }
                else
                {
                    currentIntPktLen = Tools.EndianCovert.BigToInt(currentPktLen);
                }
                rtn.Add(new Tuple<long, int>(startposition, currentIntPktLen));
                startposition += currentIntPktLen + 16;
                fileStream.Seek(startposition + 8, SeekOrigin.Begin);

            }

            fileStream.Close();
            return rtn;



        }

        static object locker =new object();
        static int startCount = 0;
        public static Packet[] ParallelReadPacket(string filePath,int threadCount,List<Tuple<long, int>> preReadList)
        {
            Packet[] rtn=new Packet[preReadList.Count];

            List<Thread> threads = new List<Thread>();

            //多线程读
            for (int ti = 0; ti < threadCount; ti++)
            {
                threads.Add(new Thread(delegate ()
                {
                    lock (locker)
                    {
                        startCount++;
                    }
                    using(FileStream fs=new(filePath, FileMode.Open, System.IO.FileAccess.Read, FileShare.ReadWrite))
                    {
                        //每个线程mod读
                        for (int i = ti; i < preReadList.Count; i += threadCount)
                        {
                            fs.Seek(preReadList[i].Item1 + 16, SeekOrigin.Begin);
                            byte[] pktData = new byte[preReadList[i].Item2];
                            var isRead = fs.Read(pktData, 0, preReadList[i].Item2);
                            if (isRead != -1)
                            {
                                //实验1
                                //var p=Packet.ParsePacket(LinkLayers.Ethernet, pktData);
                                
                                //实验2 构建哈夫曼树
                                rtn[i] = Packet.ParsePacket(LinkLayers.Ethernet, pktData);
                                ;
                            }

                        }
                    }
                    lock (locker)
                    {
                        startCount--;
                    }
                }));
                threads[ti].Start();
            }

            while (startCount > 0)
            {
                Thread.Sleep(100);
            }

            return rtn;
        }


        public static void ParallelPacketParser(string filePath, int threadCount, List<Tuple<long, int>> preReadList)
        {
            List<Thread> threads = new List<Thread>();
            scanInfo = new ScanInfo();
            List<ParallelRead> parallelReads = new List<ParallelRead>();

            //多线程读
            for (int ti = 0; ti < threadCount; ti++)
            {
                CompressEnv.ParallelRead parallelRead = new CompressEnv.ParallelRead();
                parallelRead.PreReadList = preReadList;
                parallelRead.FilePath= filePath;
                parallelRead.ThreadNum = ti;
                parallelRead.ThreadCount= threadCount;
                parallelReads.Add(parallelRead);
                threads.Add(new Thread(new ThreadStart(parallelReads[ti].DoParallelRead)));
                threads[ti].Start();
            }

            do
            {
                Thread.Sleep(100);
            } while (ParallelRead.startCount > 0);

            scanInfo.sort_dict_PKTLength= scanInfo.dict_PKTLength.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value,new ByteArrayEqualityComparer());
            int i = 0;
            foreach (var kv in scanInfo.sort_dict_PKTLength)
            {
                scanInfo.sort_dict_PKTLength[kv.Key] = i++;
            }

            scanInfo.sort_dict_Ethernet_MAC = scanInfo.dict_Ethernet_MAC.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value, new ByteArrayEqualityComparer());
            i = 0;
            foreach (var kv in scanInfo.sort_dict_Ethernet_MAC)
            {
                scanInfo.sort_dict_Ethernet_MAC[kv.Key] = i++;
            }

            scanInfo.sort_dict_Ethernet_Type = scanInfo.dict_Ethernet_Type.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value, new ByteArrayEqualityComparer());
            i = 0;
            foreach (var kv in scanInfo.sort_dict_Ethernet_Type)
            {
                scanInfo.sort_dict_Ethernet_Type[kv.Key] = i++;
            }

            scanInfo.sort_dict_Protocol = scanInfo.dict_Protocol.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value, new ByteArrayEqualityComparer());
            i = 0;
            foreach (var kv in scanInfo.sort_dict_Protocol)
            {
                scanInfo.sort_dict_Protocol[kv.Key] = i++;
            }

            scanInfo.sort_dict_IPAddress = scanInfo.dict_IPAddress.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value, new ByteArrayEqualityComparer());
            //byte[] findbs = { 74,159,192,16 };
            //var lfinddebug = scanInfo.sort_dict_IPAddress[findbs];
            i = 0;
            foreach (var kv in scanInfo.sort_dict_IPAddress)
            {
                scanInfo.sort_dict_IPAddress[kv.Key] = i++;
            }

            /*
            scanInfo.sort_dict_IPv4_Address = scanInfo.dict_IPv4_Address.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value, new ByteArrayEqualityComparer());
            i = 0;
            foreach (var kv in scanInfo.sort_dict_Ethernet_MAC)
            {
                scanInfo.sort_dict_Ethernet_MAC[kv.Key] = i++;
            }

            scanInfo.sort_dict_IPv6_Address = scanInfo.dict_IPv6_Address.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value, new ByteArrayEqualityComparer());
            i = 0;
            foreach (var kv in scanInfo.sort_dict_Ethernet_MAC)
            {
                scanInfo.sort_dict_Ethernet_MAC[kv.Key] = i++;
            }
            */

            ;
            //return rtn;
        }



        static object locker_pktlength=new object();
        static object locker_eth_mac = new object();
        static object locker_eth_type = new object();
        static object locker_protocol = new object();
        static object locker_ipaddress = new object();
        static object locker_ipv4_address = new object();
        static object locker_ipv6_address = new object();

        public static void PacketParser(byte[] pcapHeader,byte[] pktData)
        {
            //（4时间戳秒+4时间戳毫秒+4当前pcap长度+4包长度）16+pktlength


            byte[] pktLen = new byte[4];
            Array.Copy(pcapHeader, 8, pktLen, 0, 4);

                if (scanInfo.dict_PKTLength.ContainsKey(pktLen))
                {
                lock (locker_pktlength)
                {
                    scanInfo.dict_PKTLength[pktLen] += 1;
                }
                }
                else
                {
                    scanInfo.dict_PKTLength.TryAdd(pktLen, 1);
                }
                //scanInfo.PKTLengthCount.AddOrUpdate(pktLen, 1, (key, oldValue) => oldValue + 1);
            

            byte[] allMAC = new byte[12];
            Array.Copy(pktData, 0, allMAC, 0, 12);

                if (scanInfo.dict_Ethernet_MAC.ContainsKey(allMAC))
                {
                lock (locker_eth_mac)
                {
                    scanInfo.dict_Ethernet_MAC[allMAC] += 1;
                }
                }
                else
                {
                    scanInfo.dict_Ethernet_MAC.TryAdd(allMAC, 1);
                }
                //scanInfo.Ethernet_MACCount.AddOrUpdate(allMAC, 1, (key, oldValue) => oldValue + 1);
            

            byte[] allEth_Type = new byte[2];
            Array.Copy(pktData, 12, allEth_Type, 0, 2);

            if (scanInfo.dict_Ethernet_Type.ContainsKey(allEth_Type))
            {
                lock (locker_eth_type)
                {
                    scanInfo.dict_Ethernet_Type[allEth_Type] += 1;
                }
            }
            else
            {
                scanInfo.dict_Ethernet_Type.TryAdd(allEth_Type, 1);
            }
                //scanInfo.Ethernet_TypeCount.AddOrUpdate(allEth_Type, 1, (key, oldValue) => oldValue + 1);
            

            ;
            //IPv4
            if (allEth_Type[0]==0x8&& allEth_Type[1] == 0x00)
            {
                //ipv4 protocol

                byte[] protocol = new byte[1];
                Array.Copy(pktData, 0x17, protocol, 0, 1);

                    if (scanInfo.dict_Protocol.ContainsKey(protocol))
                    {
                        lock (locker_protocol)
                        {
                            scanInfo.dict_Protocol[protocol] += 1;
                        }
                    }
                    else
                    {
                        scanInfo.dict_Protocol.TryAdd(protocol, 1);
                    }
                

                byte[] ipv4address_dst = new byte[4];
                //byte[] ipv4address_dst = new byte[8];
                byte[] ipv4address_src = new byte[4];
                Array.Copy(pktData, 0x1A, ipv4address_dst, 0, 4);
                //Array.Copy(pktData, 0x1A, ipv4address_dst, 0, 8);
                Array.Copy(pktData, 0x1E, ipv4address_src, 0, 4);

                if (scanInfo.dict_IPAddress.ContainsKey(ipv4address_dst))
                {
                    lock (locker_ipaddress)
                    {
                        scanInfo.dict_IPAddress[ipv4address_dst] += 1;
                    }
                }
                else
                {
                    scanInfo.dict_IPAddress.TryAdd(ipv4address_dst, 1);
                }

                if (scanInfo.dict_IPAddress.ContainsKey(ipv4address_src))
                {
                    lock (locker_ipaddress)
                    {
                        scanInfo.dict_IPAddress[ipv4address_src] += 1;
                    }
                }
                else
                {
                    scanInfo.dict_IPAddress.TryAdd(ipv4address_src, 1);
                }

                /*
                if (scanInfo.dict_IPv4_Address.ContainsKey(ipv4address_dst))
                {
                    lock (locker_ipv4_address)
                    {
                        scanInfo.dict_IPv4_Address[ipv4address_dst] += 1;
                    }
                }
                else
                {
                    scanInfo.dict_IPv4_Address.TryAdd(ipv4address_dst, 1);
                }

                if (scanInfo.dict_IPv4_Address.ContainsKey(ipv4address_src))
                {
                    scanInfo.dict_IPv4_Address[ipv4address_src] += 1;
                }
                else
                {
                    scanInfo.dict_IPv4_Address.TryAdd(ipv4address_src, 1);
                }
                */

            }            //IPv6
            else if (allEth_Type[0] == 0x86 && allEth_Type[1] == 0xdd)
            {
                //ipv6 protocol

                byte[] protocol = new byte[1];
                Array.Copy(pktData, 0x14, protocol, 0, 1);

                if (scanInfo.dict_Protocol.ContainsKey(protocol))
                {
                    lock (locker_protocol)
                    {
                        scanInfo.dict_Protocol[protocol] += 1;
                    }
                }
                else
                {
                    scanInfo.dict_Protocol.TryAdd(protocol, 1);
                }
                

                byte[] ipv6address_dst = new byte[16];
                //byte[] ipv6address_dst = new byte[32];
                byte[] ipv6address_src = new byte[16];
                Array.Copy(pktData, 0x16, ipv6address_dst, 0, 16);
                //Array.Copy(pktData, 0x16, ipv6address_dst, 0, 32);
                Array.Copy(pktData, 0x26, ipv6address_src, 0, 16);

                if (scanInfo.dict_IPAddress.ContainsKey(ipv6address_dst))
                {
                    lock (locker_ipaddress)
                    {
                        scanInfo.dict_IPAddress[ipv6address_dst] += 1;
                    }
                }
                else
                {
                    scanInfo.dict_IPAddress.TryAdd(ipv6address_dst, 1);
                }

                if (scanInfo.dict_IPAddress.ContainsKey(ipv6address_src))
                {
                    lock (locker_ipaddress)
                    {
                        scanInfo.dict_IPAddress[ipv6address_src] += 1;
                    }
                }
                else
                {
                    scanInfo.dict_IPAddress.TryAdd(ipv6address_src, 1);
                }

                /*
                if (scanInfo.dict_IPv6_Address.ContainsKey(ipv6address_dst))
                {
                    lock (locker_ipv6_address)
                    {
                        scanInfo.dict_IPv6_Address[ipv6address_dst] += 1;
                    }
                }
                else
                {
                    scanInfo.dict_IPv6_Address.TryAdd(ipv6address_dst, 1);
                }


                if (scanInfo.dict_IPv6_Address.ContainsKey(ipv6address_src))
                {
                    scanInfo.dict_IPv6_Address[ipv6address_src] += 1;
                }
                else
                {
                    scanInfo.dict_IPv6_Address.TryAdd(ipv6address_src, 1);
                }*/


            }
        }
    }
}
