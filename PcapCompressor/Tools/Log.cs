using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.Tools
{
    internal class Log
    {
        public static void LogToFile(string message)
        {

            try
            {
                string filename =  "runningLog.txt";
                string filePath = AppDomain.CurrentDomain.BaseDirectory + filename;
                FileInfo file = new FileInfo(AppDomain.CurrentDomain.BaseDirectory + filename);
                StringBuilder sb = new StringBuilder();
                sb.Append(DateTime.Now.ToString());
                sb.Append(",");
                sb.Append(message);
                FileMode fm = new FileMode();
                if (!file.Exists)
                {
                    fm = FileMode.Create;
                }
                else
                {
                    fm = FileMode.Append;
                }
                using (FileStream fs = new FileStream(filePath, fm, FileAccess.Write, FileShare.Write))
                {
                    using (StreamWriter sw = new StreamWriter(fs, Encoding.Default))
                    {
                        sw.WriteLine(sb.ToString());
                        sw.Close();
                    }
                }
            }
            catch (Exception ex)
            {
                //return;
            }
        }
    }
}
