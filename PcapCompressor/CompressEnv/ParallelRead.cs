using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.CompressEnv
{
    internal class ParallelRead
    {
        static object locker = new object();
        static public int startCount = 0;
        string filePath;
        List<Tuple<long, int>> preReadList;
        int threadNum;
        int threadCount;


        public void DoParallelRead()
        {
            lock (locker)
            {
                startCount++;
            }
            using (FileStream fs = new(filePath, FileMode.Open, System.IO.FileAccess.Read, FileShare.ReadWrite))
            {

                //每个线程mod读
                for (int i = threadNum; i < preReadList.Count; i += threadCount)
                {
                    fs.Seek(preReadList[i].Item1, SeekOrigin.Begin);
                    byte[] pcapHeader = new byte[16];
                    var isReadH = fs.Read(pcapHeader, 0, 16);

                    byte[] pktData = new byte[preReadList[i].Item2];
                    var isRead = fs.Read(pktData, 0, preReadList[i].Item2);

                    /*
                    lock (testlocker)
                    {
                        System.Diagnostics.Debug.WriteLine(testint++ + ":" + i);
                    }
                    */

                    if (isReadH != -1 && isRead != -1)
                    {
                        PcapParser.PacketParser(pcapHeader, pktData);
                    }


                }
            }
            lock (locker)
            {
                startCount--;
            }
        }


        static int testint = 0;
        static object testlocker = new object();

        public string FilePath { get => filePath; set => filePath = value; }
        public List<Tuple<long, int>> PreReadList { get => preReadList; set => preReadList = value; }
        public int ThreadNum { get => threadNum; set => threadNum = value; }
        public int ThreadCount { get => threadCount; set => threadCount = value; }
    }
}
