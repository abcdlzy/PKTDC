using PcapCompressor.CompressEnv;
using PcapCompressor.Tools;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.Exp
{
    internal class Recover
    {
        public static void RecoverPcap(string compressFilePath,string uncompressPcapFilePath)
        {
            var scaninfo=ReadDictionary(compressFilePath);
            //var headers=ReadHeaders(compressFilePath, scaninfo);
            Stopwatch sw1 = new Stopwatch();
            sw1.Start();
            var headers = ParallelIO.ParallelReadHeaders(compressFilePath, scaninfo,Global.thread_RecoverCount);
            sw1.Stop();
            System.Diagnostics.Debug.WriteLine("parallel ream time: " + sw1.ElapsedMilliseconds);
            Tools.Log.LogToFile(compressFilePath + "," + Global.thread_ConvertCount + "," + Global.splitCount + ",Recover.ParallelIO.ParallelReadHeaders," + sw1.ElapsedMilliseconds.ToString());

            sw1.Restart();
            RecoverAllPacp(compressFilePath,uncompressPcapFilePath,headers);
            sw1.Stop();
            Tools.Log.LogToFile(compressFilePath + "," + Global.thread_ConvertCount + "," + Global.splitCount + ",Recover.RecoverAllPacp," + sw1.ElapsedMilliseconds.ToString());
            ;
        }

        public static void RecoverTargetPcap(string compressFilePath, string uncompressPcapFilePath, byte[] targetAddress)
        {
            var scaninfo = ReadDictionary(compressFilePath);
            //var headers=ReadHeaders(compressFilePath, scaninfo);
            var headers = ParallelIO.ParallelReadHeaders(compressFilePath, scaninfo, Global.thread_RecoverCount);
            RecoverAllPacp(compressFilePath, uncompressPcapFilePath, headers,targetAddress);
            ;
        }


        public static ScanInfo ReadDictionary(string compressFilePath)
        {
            ScanInfo scanInfo = new ScanInfo();

            if(Global.isSevenZipMode)
            {
                scanInfo.r_sort_dict_PKTLength = Serialization.DeserializeConcurrentDictionary(SevenZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "dict-pktLen")).ToDictionary(pair => pair.Value, pair => pair.Key);
                scanInfo.r_sort_dict_Ethernet_MAC = Serialization.DeserializeConcurrentDictionary(SevenZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "dict-MAC")).ToDictionary(pair => pair.Value, pair => pair.Key);
                scanInfo.r_sort_dict_Ethernet_Type = Serialization.DeserializeConcurrentDictionary(SevenZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "dict-type")).ToDictionary(pair => pair.Value, pair => pair.Key);
                scanInfo.r_sort_dict_Protocol = Serialization.DeserializeConcurrentDictionary(SevenZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "dict-protocol")).ToDictionary(pair => pair.Value, pair => pair.Key);
                scanInfo.r_sort_dict_IPAddress = Serialization.DeserializeConcurrentDictionary(SevenZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "dict-IPAddress")).ToDictionary(pair => pair.Value, pair => pair.Key);
            }
            else
            {
                scanInfo.r_sort_dict_PKTLength = Serialization.DeserializeConcurrentDictionary(ZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "dict-pktLen")).ToDictionary(pair => pair.Value, pair => pair.Key);
                scanInfo.r_sort_dict_Ethernet_MAC = Serialization.DeserializeConcurrentDictionary(ZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "dict-MAC")).ToDictionary(pair => pair.Value, pair => pair.Key);
                scanInfo.r_sort_dict_Ethernet_Type = Serialization.DeserializeConcurrentDictionary(ZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "dict-type")).ToDictionary(pair => pair.Value, pair => pair.Key);
                scanInfo.r_sort_dict_Protocol = Serialization.DeserializeConcurrentDictionary(ZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "dict-protocol")).ToDictionary(pair => pair.Value, pair => pair.Key);
                scanInfo.r_sort_dict_IPAddress = Serialization.DeserializeConcurrentDictionary(ZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "dict-IPAddress")).ToDictionary(pair => pair.Value, pair => pair.Key);
            }


            return scanInfo;
        }

        enum L3Mode { NotSet,IPv4,IPv6,Other };

        public static HeaderCollection ReadHeaders(string compressFilePath,ScanInfo scanInfo)
        {
            HeaderCollection headerCollection = new HeaderCollection();

            if(Global.isSevenZipMode)
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

            byte[] headerBytes;
            if (Global.isSevenZipMode)
            {
                headerBytes = SevenZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "header").ToArray();
            }
            else
            {
                headerBytes = ZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "header").ToArray();
            }



            int currentBitPosition = 0;
            List<bool> currentPktBits=new List<bool>();
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

            for (long i = 0; i < headerBytes.LongLength; i++)
            {
                var nowbits = BitByteConvert.ByteToBits(headerBytes[i]);

                for (int j = 0; j < 8; j++)
                {
                    if (currentBitPosition == 0)
                    {
                        currentL3Mode=L3Mode.NotSet;
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
                    else if (currentL3Mode != L3Mode.Other && currentBitPosition >= pktlenBitCount + macBitCount+ bitCount_eth_Type && currentBitPosition < pktlenBitCount + macBitCount + bitCount_eth_Type+ protocolbitCount)
                    {
                        //protocol
                        currentprotocolBits.Add(nowbits[j]);
                    }
                    else if(currentL3Mode != L3Mode.Other && currentBitPosition >= pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount)
                    {
                        if(currentBitPosition < pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount + ipaddrbitCount)
                        {
                            currentIPAddrBits_dst.Add(nowbits[j]);
                        }
                        
                        else if (currentBitPosition >= pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount + ipaddrbitCount && currentBitPosition < pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount + 2* ipaddrbitCount)
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
                    if (currentL3Mode == L3Mode.Other && currentBitPosition == pktlenBitCount + macBitCount + bitCount_eth_Type)
                    {
                        currentPktLocation = BitByteConvert.BitsToInt(currentPktBits.ToArray());
                        currentMACLocation = BitByteConvert.BitsToInt(currentMACBits.ToArray());
                        currentEhtTypeLocation = BitByteConvert.BitsToInt(currentEthTypeBits.ToArray());

                        var newheader=new Header();

                        newheader.pktlen = scanInfo.r_sort_dict_PKTLength[currentPktLocation];
                        newheader.MAC = scanInfo.r_sort_dict_Ethernet_MAC[currentMACLocation];
                        newheader.type = scanInfo.r_sort_dict_Ethernet_Type[currentEhtTypeLocation];

                        headerCollection.headerList.Add(newheader);
                        currentPktBits.Clear();
                        currentMACBits.Clear();
                        currentEthTypeBits.Clear();
                        currentprotocolBits.Clear();
                        currentIPAddrBits_dst.Clear();
                        currentIPAddrBits_src.Clear();
                        currentBitPosition = 0;
                    }
                    else if ((currentL3Mode == L3Mode.IPv4|| currentL3Mode == L3Mode.IPv6) && currentBitPosition == pktlenBitCount + macBitCount + bitCount_eth_Type + protocolbitCount + 2*ipaddrbitCount)
                    {
                        currentPktLocation = BitByteConvert.BitsToInt(currentPktBits.ToArray());
                        currentMACLocation = BitByteConvert.BitsToInt(currentMACBits.ToArray());
                        currentEhtTypeLocation = BitByteConvert.BitsToInt(currentEthTypeBits.ToArray());
                        currentprotocolLocation= BitByteConvert.BitsToInt(currentprotocolBits.ToArray());
                        currentIPAddrLocation_dst = BitByteConvert.BitsToInt(currentIPAddrBits_dst.ToArray());
                        currentIPAddrLocation_src = BitByteConvert.BitsToInt(currentIPAddrBits_src.ToArray());

                        var newheader = new Header();

                        newheader.pktlen = scanInfo.r_sort_dict_PKTLength[currentPktLocation];
                        newheader.MAC = scanInfo.r_sort_dict_Ethernet_MAC[currentMACLocation];
                        newheader.type = scanInfo.r_sort_dict_Ethernet_Type[currentEhtTypeLocation];
                        newheader.protocol = scanInfo.r_sort_dict_Protocol[currentprotocolLocation];
                        newheader.IPAddress_dst = scanInfo.r_sort_dict_IPAddress[currentIPAddrLocation_dst];
                        newheader.IPAddress_src = scanInfo.r_sort_dict_IPAddress[currentIPAddrLocation_src];

                        headerCollection.headerList.Add(newheader);
                        currentPktBits.Clear();
                        currentMACBits.Clear();
                        currentEthTypeBits.Clear();
                        currentprotocolBits.Clear();
                        currentIPAddrBits_dst.Clear();
                        currentIPAddrBits_src.Clear();
                        currentBitPosition = 0;
                    }
                    
                }
                if (i % 1000000 == 0)
                {
                    System.Diagnostics.Debug.WriteLine(i);
                }
            }

            return headerCollection;

        }

        public static void RecoverAllPacp(string compressFilePath, string uncompressPcapFilePath,HeaderCollection headerCollection)
        {

            using (FileStream fileStream = new FileStream(uncompressPcapFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
            {
                fileStream.Write(headerCollection.pcapHeader);

                for (int payloadCount = 0; payloadCount <= headerCollection.headerList.Count / Global.splitCount; payloadCount++)
                {
                    HugeMemoryStream readPayload;
                    if (Global.isSevenZipMode)
                    {
                        readPayload = SevenZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "payload-" + ((payloadCount) + 1));
                    }
                    else
                    {
                        readPayload = ZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "payload-" + ((payloadCount) + 1));
                    }


                    readPayload.Seek(0, SeekOrigin.Begin);
                    for (int i = payloadCount * Global.splitCount; i < headerCollection.headerList.Count && i < (payloadCount + 1) * Global.splitCount; i++)
                    {
                        //获取单个数据包   //写头8B，跳4B当前包长度，再写4B整包长度，再跳14B MAC+type，再读完
                        //先读8B，然后写pktlen，然后再读4B，然后写MAC，再写ethtype，再读完

                        int currentIntPktLen = 0;
                        if (headerCollection.isLittleEndian)
                        {
                            currentIntPktLen = Tools.EndianCovert.LittleToInt(headerCollection.headerList[i].pktlen);
                        }
                        else
                        {
                            currentIntPktLen = Tools.EndianCovert.BigToInt(headerCollection.headerList[i].pktlen);
                        }

                        var currentPkt = new byte[currentIntPktLen + 16];

                        readPayload.Read(currentPkt, 0, 8);
                        Array.Copy(headerCollection.headerList[i].pktlen, 0, currentPkt, 8, 4);
                        readPayload.Read(currentPkt, 12, 4);
                        Array.Copy(headerCollection.headerList[i].MAC, 0, currentPkt, 16, 12);
                        Array.Copy(headerCollection.headerList[i].type, 0, currentPkt, 28, 2);

                        //ipv4
                        if (headerCollection.headerList[i].type[0] == 0x8 && headerCollection.headerList[i].type[1] == 0x00)
                        {
                            readPayload.Read(currentPkt, 30, 9);
                            Array.Copy(headerCollection.headerList[i].protocol, 0, currentPkt, 39, 1);
                            readPayload.Read(currentPkt, 40, 2);
                            Array.Copy(headerCollection.headerList[i].IPAddress_dst, 0, currentPkt, 42, 4);
                            Array.Copy(headerCollection.headerList[i].IPAddress_src, 0, currentPkt, 46, 4);
                            readPayload.Read(currentPkt, 50, currentIntPktLen - 34);
                        }
                        //ipv6
                        else if (headerCollection.headerList[i].type[0] == 0x86 && headerCollection.headerList[i].type[1] == 0xdd)
                        {
                            readPayload.Read(currentPkt, 30, 6);
                            Array.Copy(headerCollection.headerList[i].protocol, 0, currentPkt, 36, 1);
                            readPayload.Read(currentPkt, 37, 1);
                            Array.Copy(headerCollection.headerList[i].IPAddress_dst, 0, currentPkt, 38,16);
                            Array.Copy(headerCollection.headerList[i].IPAddress_src, 0, currentPkt, 54,16);
                            readPayload.Read(currentPkt, 70, currentIntPktLen - 54);
                        }
                        //other
                        else
                        {
                            readPayload.Read(currentPkt, 30, currentIntPktLen - 14);
                        }

                        
                        fileStream.Write(currentPkt);
                        ;
                    }
                    System.Diagnostics.Debug.WriteLine(payloadCount);
                }
            }
        }

        public static void RecoverAllPacp(string compressFilePath, string uncompressPcapFilePath, HeaderCollection headerCollection, byte[] targetAddress)
        {

            using (FileStream fileStream = new FileStream(uncompressPcapFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
            {
                fileStream.Write(headerCollection.pcapHeader);

                for (int payloadCount = 0; payloadCount <= headerCollection.headerList.Count / Global.splitCount; payloadCount++)
                {



                    bool isInit = false;
                    long offsetLength = 0;
                    HugeMemoryStream readPayload = new HugeMemoryStream();

                    for (int i = payloadCount * Global.splitCount; i < headerCollection.headerList.Count && i < (payloadCount + 1) * Global.splitCount; i++)
                    {
                        int currentIntPktLen = 0;
                        if (headerCollection.isLittleEndian)
                        {
                            currentIntPktLen = Tools.EndianCovert.LittleToInt(headerCollection.headerList[i].pktlen);
                        }
                        else
                        {
                            currentIntPktLen = Tools.EndianCovert.BigToInt(headerCollection.headerList[i].pktlen);
                        }

               
                        if (!(Tools.ByteTools.ByteArrayEqual(headerCollection.headerList[i].IPAddress_src, targetAddress) || Tools.ByteTools.ByteArrayEqual(headerCollection.headerList[i].IPAddress_dst, targetAddress)))
                        {

                            if (headerCollection.headerList[i].type[0] == 0x8 && headerCollection.headerList[i].type[1] == 0x00)
                            {
                                offsetLength += (currentIntPktLen - 11);
                            }
                            else if (headerCollection.headerList[i].type[0] == 0x86 && headerCollection.headerList[i].type[1] == 0xdd)
                            {
                                offsetLength += (currentIntPktLen - 35);
                            }
                            else
                            {
                                offsetLength += (currentIntPktLen - 2);
                            }
                            
                            continue;
                        }

                            
                        
 
                        if (!isInit)
                        {
                            if (Global.isSevenZipMode)
                            {
                                readPayload = SevenZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "payload-" + ((payloadCount) + 1));
                            }
                            else
                            {
                                readPayload = ZipArchiveHelper.ReadFileFromZipArchive(compressFilePath, "payload-" + ((payloadCount) + 1));
                            }
                            readPayload.Seek(0, SeekOrigin.Begin);
                            isInit = true;
                        }

                        if (offsetLength > 0)
                        {
                            readPayload.Seek(offsetLength, SeekOrigin.Current);
                            offsetLength = 0;
                        }

                        //获取单个数据包   //写头8B，跳4B当前包长度，再写4B整包长度，再跳14B MAC+type，再读完
                        //先读8B，然后写pktlen，然后再读4B，然后写MAC，再写ethtype，再读完



                        var currentPkt = new byte[currentIntPktLen + 16];

                        readPayload.Read(currentPkt, 0, 8);
                        Array.Copy(headerCollection.headerList[i].pktlen, 0, currentPkt, 8, 4);
                        readPayload.Read(currentPkt, 12, 4);
                        Array.Copy(headerCollection.headerList[i].MAC, 0, currentPkt, 16, 12);
                        Array.Copy(headerCollection.headerList[i].type, 0, currentPkt, 28, 2);

                        //ipv4
                        if (headerCollection.headerList[i].type[0] == 0x8 && headerCollection.headerList[i].type[1] == 0x00)
                        {
                            readPayload.Read(currentPkt, 30, 9);
                            Array.Copy(headerCollection.headerList[i].protocol, 0, currentPkt, 39, 1);
                            readPayload.Read(currentPkt, 40, 2);
                            Array.Copy(headerCollection.headerList[i].IPAddress_dst, 0, currentPkt, 42, 4);
                            Array.Copy(headerCollection.headerList[i].IPAddress_src, 0, currentPkt, 46, 4);
                            readPayload.Read(currentPkt, 50, currentIntPktLen - 34);
                        }
                        //ipv6
                        else if (headerCollection.headerList[i].type[0] == 0x86 && headerCollection.headerList[i].type[1] == 0xdd)
                        {
                            readPayload.Read(currentPkt, 30, 6);
                            Array.Copy(headerCollection.headerList[i].protocol, 0, currentPkt, 36, 1);
                            readPayload.Read(currentPkt, 37, 1);
                            Array.Copy(headerCollection.headerList[i].IPAddress_dst, 0, currentPkt, 38, 16);
                            Array.Copy(headerCollection.headerList[i].IPAddress_src, 0, currentPkt, 54, 16);
                            readPayload.Read(currentPkt, 70, currentIntPktLen - 54);
                        }
                        //other
                        else
                        {
                            readPayload.Read(currentPkt, 30, currentIntPktLen - 14);
                        }


                        fileStream.Write(currentPkt);
                        ;
                    }
                    System.Diagnostics.Debug.WriteLine(payloadCount);
                }
            }
        }

    }
}
