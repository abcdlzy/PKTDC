using PcapCompressor.Tools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.CompressEnv
{
    internal class ParallelSavePayload
    {
        static object locker = new object();
        static public int startCount = 0;
        public string filePath;
        public string zipFilePath;
        public List<Tuple<long, int>> preReadList;
        public List<int> taskBlock=new List<int>();
        int threadNum;
        int threadCount;

        /// <summary>
        /// 每个线程单独处理一个块
        /// </summary>
        public void DoParallelSavePayload()
        {
            lock (locker)
            {
                Interlocked.Increment(ref startCount);
            }

            //计算要开始处理的位置
            for(int tb=0;tb<taskBlock.Count;tb++)
            {
                HugeMemoryStream memoryStream = new HugeMemoryStream();
                FileStream pcapfileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                int endPkt = (taskBlock[tb]+1) * Global.splitCount > preReadList.Count ? preReadList.Count : (taskBlock[tb] + 1) * Global.splitCount;
                //开始连续处理
                for (int i= taskBlock[tb] * Global.splitCount; i< endPkt; i++)
                {
                    //写头8B，跳4B时间，再写4B整包长度，再跳14B，再读完
                    pcapfileStream.Seek(preReadList[i].Item1, SeekOrigin.Begin);
                    byte[] readHeaderBytes = new byte[12];

                    pcapfileStream.Read(readHeaderBytes, 0, 8);
                    //包长度
                    pcapfileStream.Seek(4, SeekOrigin.Current);
                    pcapfileStream.Read(readHeaderBytes, 8, 4);

                    //2层
                    pcapfileStream.Seek(12, SeekOrigin.Current);
                    //读取类型
                    byte[] l3type = new byte[2];
                    pcapfileStream.Read(l3type, 0, 2);
                    byte[] readBytes = null;

                    if (l3type[0] == 0x8 && l3type[1] == 0x00)
                    {
                        byte[] readIPv4Bytes = new byte[preReadList[i].Item2 - 23];
                        //protocol
                        pcapfileStream.Read(readIPv4Bytes, 0, 9);
                        pcapfileStream.Seek(1, SeekOrigin.Current);
                        //addr
                        pcapfileStream.Read(readIPv4Bytes, 9, 2);
                        pcapfileStream.Seek(8, SeekOrigin.Current);
                        pcapfileStream.Read(readIPv4Bytes, 11, preReadList[i].Item2 - 34);

                        readBytes = new byte[readIPv4Bytes.Length + 12];
                        Array.Copy(readHeaderBytes, readBytes, readHeaderBytes.Length);
                        Array.Copy(readIPv4Bytes, 0, readBytes, readHeaderBytes.Length, readIPv4Bytes.Length);
                    }
                    //IPv6
                    else if (l3type[0] == 0x86 && l3type[1] == 0xdd)
                    {
                        byte[] readIPv6Bytes = new byte[preReadList[i].Item2 - 47];
                        //protocol
                        pcapfileStream.Read(readIPv6Bytes, 0, 6);
                        pcapfileStream.Seek(1, SeekOrigin.Current);
                        //addr
                        pcapfileStream.Read(readIPv6Bytes, 6, 1);
                        pcapfileStream.Seek(0x20, SeekOrigin.Current);
                        pcapfileStream.Read(readIPv6Bytes, 7, preReadList[i].Item2 - 54);

                        readBytes = new byte[readIPv6Bytes.Length + 12];
                        Array.Copy(readHeaderBytes, readBytes, readHeaderBytes.Length);
                        Array.Copy(readIPv6Bytes, 0, readBytes, readHeaderBytes.Length, readIPv6Bytes.Length);
                    }
                    else
                    {
                        byte[] readOtherBytes = new byte[preReadList[i].Item2 - 14];
                        pcapfileStream.Read(readOtherBytes, 0, preReadList[i].Item2 - 14);


                        readBytes = new byte[readOtherBytes.Length + 12];
                        Array.Copy(readHeaderBytes, readBytes, readHeaderBytes.Length);
                        Array.Copy(readOtherBytes, 0, readBytes, readHeaderBytes.Length, readOtherBytes.Length);
                    }

                    //写包
                    memoryStream.Write(readBytes, 0, readBytes.Length);
                }

                pcapfileStream.Close();

                //将连续处理完成的结果存储到memorystream等待集中压缩
                if (Global.isSevenZipMode)
                {
                    SevenZipArchiveHelper.AddToZipArchive(zipFilePath, "payload-" +(taskBlock[tb] + 1), memoryStream);
                }
                else
                {
                    ZipArchiveHelper.AddToZipArchive(zipFilePath, "payload-" + (taskBlock[tb] + 1), memoryStream);
                }
            }

            lock (locker)
            {
                Interlocked.Decrement(ref startCount);
            }
        }
    }
}
