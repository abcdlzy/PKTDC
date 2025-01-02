using PcapCompressor.Tools;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.CompressEnv
{
    internal class ParallelRecover
    {
        static public int startCount = 0;
        public int threadNum;
        public int threadCount;
        public ScanInfo scanInfo;
        public ConcurrentQueue<byte[]> waitForProcessQueues;

        public int pktlenBitCount;
        public int macBitCount;
        public int bitCount_eth_Type;
        public int protocolbitCount;
        public int ipaddrbitCount;

        public bool isLoadFinished = false;


        enum L3Mode { NotSet, IPv4, IPv6, Other };
        public void DoParallelReadHeaders()
        {
            #region init
            int currentBitPosition = 0;
            List<bool> currentPktBits = new List<bool>();
            int currentPktLocation = 0;
            List<bool> currentMACBits = new List<bool>();
            int currentMACLocation = 0;
            List<bool> currentEthTypeBits = new List<bool>();
            int currentEhtTypeLocation = 0;

            List<bool> currentprotocolBits = new List<bool>();
            int currentprotocolLocation = 0;
            List<bool> currentIPAddrBits_src = new List<bool>();
            int currentIPAddrLocation_src = 0;
            List<bool> currentIPAddrBits_dst = new List<bool>();
            int currentIPAddrLocation_dst = 0;

            L3Mode currentL3Mode = L3Mode.NotSet;
            #endregion
            while (!(isLoadFinished&&waitForProcessQueues.Count==0))
            {
                if(waitForProcessQueues.Count == 0)
                {
                    Thread.Sleep(1);
                }
                else
                {
                    //从队列读取处理
                    byte[] getBytes;
                    if(!waitForProcessQueues.TryDequeue(out getBytes))
                    {
                        continue;
                    }
                    
                    List<Header> pushHeaders=new List<Header>();

                    for (long i = 0; i < getBytes.LongLength; i++)
                    {
                        var nowbits = BitByteConvert.ByteToBits(getBytes[i]);

                        for (int j = 0; j < 8; j++)
                        {
                            if (currentBitPosition == 0)
                            {
                                currentL3Mode = L3Mode.NotSet;
                            }

                            if (currentBitPosition < pktlenBitCount)
                            {
                                //readpktbits
                                currentPktBits.Add(nowbits[j]);
                            }
                            else if (currentBitPosition >= pktlenBitCount && currentBitPosition < pktlenBitCount + macBitCount)
                            {
                                //macbits
                                currentMACBits.Add(nowbits[j]);
                            }
                            else if (currentBitPosition >= pktlenBitCount + macBitCount && currentBitPosition < pktlenBitCount + macBitCount + bitCount_eth_Type)
                            {
                                //ethtype
                                currentEthTypeBits.Add(nowbits[j]);
                            }
                            else if (currentL3Mode != L3Mode.Other && currentBitPosition >= pktlenBitCount + macBitCount + bitCount_eth_Type && currentBitPosition < pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount)
                            {
                                //protocol
                                currentprotocolBits.Add(nowbits[j]);
                            }
                            else if (currentL3Mode != L3Mode.Other && currentBitPosition >= pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount)
                            {
                                if (currentBitPosition < pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount + ipaddrbitCount)
                                {
                                    currentIPAddrBits_dst.Add(nowbits[j]);
                                }

                                else if (currentBitPosition >= pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount + ipaddrbitCount && currentBitPosition < pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount + 2 * ipaddrbitCount)
                                {
                                    currentIPAddrBits_src.Add(nowbits[j]);
                                }

                            }

                            //处理位置
                            currentBitPosition++;

                            if (currentBitPosition == pktlenBitCount + macBitCount + bitCount_eth_Type)
                            {
                                currentEhtTypeLocation = BitByteConvert.BitsToInt(currentEthTypeBits.ToArray());
                                var typeBytes = scanInfo.r_sort_dict_Ethernet_Type[currentEhtTypeLocation];
                                if (typeBytes[0] == 0x8 && typeBytes[1] == 0x00)
                                {
                                    currentL3Mode = L3Mode.IPv4;
                                }
                                else if (typeBytes[0] == 0x86 && typeBytes[1] == 0xdd)
                                {
                                    currentL3Mode = L3Mode.IPv6;
                                }
                                else
                                {
                                    currentL3Mode = L3Mode.Other;
                                }
                            }

                            //完成读取后转换                        
                            if (currentL3Mode != L3Mode.NotSet && currentBitPosition == pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount + 2 * ipaddrbitCount)
                            {
                                currentPktLocation = BitByteConvert.BitsToInt(currentPktBits.ToArray());
                                currentMACLocation = BitByteConvert.BitsToInt(currentMACBits.ToArray());
                                currentEhtTypeLocation = BitByteConvert.BitsToInt(currentEthTypeBits.ToArray());
                                currentprotocolLocation = BitByteConvert.BitsToInt(currentprotocolBits.ToArray());
                                currentIPAddrLocation_dst = BitByteConvert.BitsToInt(currentIPAddrBits_dst.ToArray());
                                currentIPAddrLocation_src = BitByteConvert.BitsToInt(currentIPAddrBits_src.ToArray());

                                var newheader = new Header();

                                newheader.pktlen = scanInfo.r_sort_dict_PKTLength[currentPktLocation];
                                newheader.MAC = scanInfo.r_sort_dict_Ethernet_MAC[currentMACLocation];
                                newheader.type = scanInfo.r_sort_dict_Ethernet_Type[currentEhtTypeLocation];
                                if(currentprotocolLocation!=Math.Pow(2,currentprotocolBits.Count)&& currentIPAddrLocation_dst != Math.Pow(2, currentIPAddrBits_dst.Count) && currentIPAddrLocation_src != Math.Pow(2, currentIPAddrBits_src.Count))
                                {
                                    newheader.protocol = scanInfo.r_sort_dict_Protocol[currentprotocolLocation];
                                    newheader.IPAddress_dst = scanInfo.r_sort_dict_IPAddress[currentIPAddrLocation_dst];
                                    newheader.IPAddress_src = scanInfo.r_sort_dict_IPAddress[currentIPAddrLocation_src];
                                }

                                pushHeaders.Add(newheader);
                                currentPktBits.Clear();
                                currentMACBits.Clear();
                                currentEthTypeBits.Clear();
                                currentprotocolBits.Clear();
                                currentIPAddrBits_dst.Clear();
                                currentIPAddrBits_src.Clear();
                                currentBitPosition = 0;
                            }

                        }
                    }

                    ParallelIO.queues_header[threadNum].Enqueue(pushHeaders);
                }
            }


        }

    }
}
