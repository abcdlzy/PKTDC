using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor
{
    internal class Global
    {
        public static readonly string sevenZipDLLPath = @"7z.dll";
        public static int splitCount = 1000000;
        public static int thread_ConvertCount = 1;
        public static int thread_FileCount = 1;
        public static int thread_RecoverCount = 1;
        public static readonly bool isSevenZipMode = true;

        public static void setThreadCount(int threadCount)
        {
            thread_ConvertCount = threadCount;
            thread_FileCount=threadCount;
            thread_RecoverCount=threadCount;
        }
    }
}
