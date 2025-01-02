using PacketDotNet;
using PcapCompressor.CompressEnv;
using PcapCompressor.Exp;
using PcapCompressor.Tools;
using SevenZip;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace PcapCompressor
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void btnRun_Click(object sender, EventArgs e)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            string filePath = @"C:\project\PcapCompressor\202304021400.pcap";
            //string filePath = @"C:\project\PcapCompressor\test.pcap";
            var pktPositionList = PcapParser.PreRead(filePath);
            PcapParser.ParallelPacketParser(filePath, Global.thread_FileCount, pktPositionList);

            #region 实验对比1
            /*
            var device = new SharpPcap.LibPcap.CaptureFileReaderDevice(filePath);
            device.Open();

            List<RawCapture> rawCaptures = new List<RawCapture>();
            Packet[] rtn = new Packet[52284335];
            int nowcount = 0;
            while (device.GetNextPacket(out PacketCapture packet) > 0)
           {
                //rtn[nowcount]=packet.GetPacket().GetPacket();
                var p= packet.GetPacket().GetPacket();
                //nowcount++;
               

           }
           device.Close();
            */
            #endregion
            #region exp
            //List<Tuple<IntPtr, IntPtr>> captures = new List<Tuple<IntPtr, IntPtr>>();
            /*
                   Parallel.ForEach(PcapDevice.GetSequence(device), rawCapture => {

                       rawCaptures.Add(rawCapture);
                   });
            */

            /*
            while (Tools.PcapReader.GetNextPacket(device.Handle,out IntPtr header,out IntPtr data) > 0)
            {

                int iDataLen = 64;

                byte[] byData = new byte[128];
                Marshal.Copy(header, byData, 0, iDataLen);
                string strData = System.Text.Encoding.ASCII.GetString(byData);

                captures.Add(new Tuple<IntPtr, IntPtr>(header, data));
            }            */
            #endregion
            sw.Stop();

            MessageBox.Show(sw.ElapsedMilliseconds.ToString());



        }

        private void btnsave_Click(object sender, EventArgs e)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            //string pcapfilePath = @"C:\project\PcapCompressor\202304021400.pcap";
            //string pcapfilePath = @"C:\project\PcapCompressor\test.pcap";
            //string binfilePath = @"C:\project\PcapCompressor\hearder-t.7z";
            string pcapfilePath = tbSourceFile.Text;
            string binfilePath = tbOutputPath.Text;

            if (File.Exists(binfilePath))
            {
                File.Delete(binfilePath);
            }

            Stopwatch swlog = new Stopwatch();
            swlog.Start();
            var pktPositionList = PcapParser.PreRead(pcapfilePath);
            swlog.Stop();
            Tools.Log.LogToFile(tbSourceFile.Text + "," + Global.thread_ConvertCount + "," + Global.splitCount + ",PcapParser.PreRead," + swlog.ElapsedMilliseconds.ToString());


            swlog.Restart();
            PcapParser.ParallelPacketParser(pcapfilePath, Global.thread_FileCount, pktPositionList);
            swlog.Stop();
            Tools.Log.LogToFile(tbSourceFile.Text + "," + Global.thread_ConvertCount + "," + Global.splitCount + ",PcapParser.ParallelPacketParser," + swlog.ElapsedMilliseconds.ToString());

            //Exp.Extract.SaveHeadersToFile(pcapfilePath, @"C:\project\PcapCompressor\hearder-t-s.bin");

            swlog.Restart();
            Exp.Extract.MultiThreadDoubleCompressSaveHeadersToFile(pcapfilePath, binfilePath, pktPositionList, PcapParser.scanInfo);
            swlog.Stop();
            Tools.Log.LogToFile(tbSourceFile.Text + "," + Global.thread_ConvertCount + "," + Global.splitCount + ",Extract.MultiThreadDoubleCompressSaveHeadersToFile," + swlog.ElapsedMilliseconds.ToString());

            swlog.Restart();
            Exp.Extract.SaveDictionaryToZipArchive(binfilePath, PcapParser.scanInfo);
            swlog.Stop();
            Tools.Log.LogToFile(tbSourceFile.Text + "," + Global.thread_ConvertCount + "," + Global.splitCount + ",Extract.SaveDictionaryToZipArchive," + swlog.ElapsedMilliseconds.ToString());

            //Exp.Extract.DoubleCompressSaveHeadersToFile(pcapfilePath, binfilePath);

            swlog.Restart();
            Exp.Extract.SavePayloadToZipArchive(pcapfilePath, binfilePath, pktPositionList);
            swlog.Stop();
            Tools.Log.LogToFile(tbSourceFile.Text + "," + Global.thread_ConvertCount + "," + Global.splitCount + ",Extract.SavePayloadToZipArchive," + swlog.ElapsedMilliseconds.ToString());

            sw.Stop();
            tbMsg.Text += "[" + DateTime.Now + "] " + tbSourceFile.Text + " 压缩至 " + tbOutputPath.Text + " 完成，耗时：" + sw.ElapsedMilliseconds.ToString() + " 毫秒\r\n";

            Tools.Log.LogToFile(tbSourceFile.Text + "," + Global.thread_ConvertCount + "," + Global.splitCount + ",SAVE," + sw.ElapsedMilliseconds.ToString());
        }

        private void btnRecovery_Click(object sender, EventArgs e)
        {
            string binfilePath = tbSourceFile.Text;
            string recoverFilePath = tbOutputPath.Text;

            //string binfilePath = @"C:\project\PcapCompressor\hearder-t.7z";
            //string recoverFilePath = @"C:\project\PcapCompressor\recover.pcap";

            if (File.Exists(recoverFilePath))
            {
                File.Delete(recoverFilePath);
            }
            Stopwatch sw = new Stopwatch();
            sw.Start();
            Exp.Recover.RecoverPcap(binfilePath, recoverFilePath);
            sw.Stop();
            tbMsg.Text += "[" + DateTime.Now + "] " + tbSourceFile.Text + " 全恢复至 " + tbOutputPath.Text + " 完成，耗时：" + sw.ElapsedMilliseconds.ToString() + " 毫秒\r\n";

            Tools.Log.LogToFile(tbSourceFile.Text + "," + Global.thread_ConvertCount + "," + Global.splitCount + ",Recover.RecoverPcap," + sw.ElapsedMilliseconds.ToString());
        }

        private void btnSaveSrc_Click(object sender, EventArgs e)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            var pcapfilePath = tbSourceFile.Text;
            Exp.Extract.SaveHeadersToFile(pcapfilePath, tbOutputPath.Text);
            sw.Stop();
            tbMsg.Text += "[" + DateTime.Now + "] " + tbSourceFile.Text + " 保存原始文件头完成，耗时：" + sw.ElapsedMilliseconds.ToString() + " 毫秒\r\n";
        }

        private void btnTest_Click(object sender, EventArgs e)
        {
            SevenZip.SevenZipCompressor.SetLibraryPath(@"7z.dll");


            var archivePath = "C:\\project\\PcapCompressor\\testOutput.7z";
            //var stream = System.IO.File.OpenRead(@"C:\project\PcapCompressor\test.pcap");
            var inputpath = @"C:\project\PcapCompressor\hearder-t\dict-pktLen";
            var inputpath1 = @"C:\project\PcapCompressor\hearder-t\dict-IPAddress";
            //var outputStream = new FileStream(archivePath, FileMode.Append, FileAccess.Write);
            //SevenZipCompressor compressor = new SevenZipCompressor();
            //compressor.TempFolderPath = "C:\\project\\PcapCompressor\\hearder-t\\";
            //string[] filenames = { inputpath, inputpath1 };
            //compressor.CompressFiles(archivePath, filenames);

            using (FileStream ostream = new FileStream(archivePath, FileMode.OpenOrCreate, FileAccess.Write))
            {
                using (FileStream istream = new FileStream(inputpath, FileMode.Open, FileAccess.Read))
                using (FileStream istream1 = new FileStream(inputpath1, FileMode.Open, FileAccess.Read))
                using (FileStream istream2 = new FileStream(inputpath1, FileMode.Open, FileAccess.Read))
                {
                    SevenZipCompressor compressor = new SevenZipCompressor();
                    compressor.CompressionLevel = CompressionLevel.Ultra;
                    compressor.CompressionMethod = CompressionMethod.Lzma2;

                    // 这里可以输入多个文件名/流对
                    Dictionary<string, Stream> dict = new Dictionary<string, Stream> { { "test11.pcap", istream }, { "test12.pcap", istream1 }, { "test13.pcap", istream2 } };

                    compressor.CompressStreamDictionary(dict, ostream);
                }
            }

            //outputStream.Close();
            //stream.Close();

        }

        private void btnRecoveryTargetPkt_Click(object sender, EventArgs e)
        {
            string binfilePath = tbSourceFile.Text;
            string recoverFilePath = tbOutputPath.Text;

            //string binfilePath = @"C:\project\PcapCompressor\hearder-t.7z";
            //string recoverFilePath = @"C:\project\PcapCompressor\recover.pcap";

            if (File.Exists(recoverFilePath))
            {
                File.Delete(recoverFilePath);
            }
            Stopwatch sw = new Stopwatch();
            sw.Start();

            var split = tbFindIP.Text.Split('.');

            byte[] findAddrBytes = { (byte)int.Parse(split[0]), (byte)int.Parse(split[1]), (byte)int.Parse(split[2]), (byte)int.Parse(split[3]) };
            Exp.Recover.RecoverTargetPcap(binfilePath, recoverFilePath, findAddrBytes);
            sw.Stop();
            tbMsg.Text += "[" + DateTime.Now + "] " + tbSourceFile.Text + " 提取 " + tbFindIP.Text + " 完成，耗时：" + sw.ElapsedMilliseconds.ToString() + " 毫秒\r\n";
        }

        private void btnSourceFile_Click(object sender, EventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            fileDialog.RestoreDirectory = true;
            fileDialog.Multiselect = true;
            fileDialog.Title = "请选择文件";
            fileDialog.Filter = "所有文件(*.*)|*.*|网络数据包(*.pcap*)|*.pcap*|压缩包(*.7z*)|*.7z*"; //设置要选择的文件的类型
            if (fileDialog.ShowDialog() == DialogResult.OK)
            {
                string file = fileDialog.FileName;//返回文件的完整路径
                tbSourceFile.Text = file;
            }
        }

        private void btnOutputFile_Click(object sender, EventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog();
            //设置文件类型 
            sfd.Filter = "所有文件(*.*)|*.*|网络数据包(*.pcap*)|*.pcap*|压缩包(*.7z*)|*.7z*";

            //设置默认文件类型显示顺序 
            sfd.FilterIndex = 1;

            //保存对话框是否记忆上次打开的目录 
            sfd.RestoreDirectory = true;

            //点了保存按钮进入 
            if (sfd.ShowDialog() == DialogResult.OK)
            {
                tbOutputPath.Text = sfd.FileName.ToString(); //获得文件路径 
            }
        }

        private void label3_Click(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            tbThreadCount.Text = Global.thread_ConvertCount.ToString();
        }

        private void btnSetThreadCount_Click(object sender, EventArgs e)
        {
            Global.setThreadCount(int.Parse(tbThreadCount.Text));
            tbThreadCount.Text = Global.thread_ConvertCount.ToString();
            tbMsg.Text += "[" + DateTime.Now + "] total thread set to " + tbThreadCount.Text + " \r\n";
        }

        private void tbMsg_TextChanged(object sender, EventArgs e)
        {
            tbMsg.SelectionStart = tbMsg.Text.Length; //Set the current caret position at the end
            tbMsg.ScrollToCaret(); //Now scroll it automatically
        }

        private void btnAutoTest_Click(object sender, EventArgs e)
        {
            //int[] testThreadCount = { 1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 2000, 3000, 4000, 5000 };
            int[] testThreadCount = { 1 };
            string[] testSourcePath = { @"C:\project\PcapCompressor\1m\1m.pcap",
                @"C:\project\PcapCompressor\10m\10m.pcap",
                @"C:\project\PcapCompressor\20m\20m.pcap",
                @"C:\project\PcapCompressor\30m\30m.pcap",
                @"C:\project\PcapCompressor\40m\40m.pcap",
                @"C:\project\PcapCompressor\50m\50m.pcap",
                @"C:\project\PcapCompressor\all\all.pcap" };

            string[] testOutputPath = { @"C:\project\PcapCompressor\1m\1m-dict.7z",
                @"C:\project\PcapCompressor\10m\10m-dict.7z",
                @"C:\project\PcapCompressor\20m\20m-dict.7z",
                @"C:\project\PcapCompressor\30m\30m-dict.7z",
                @"C:\project\PcapCompressor\40m\40m-dict.7z",
                @"C:\project\PcapCompressor\50m\50m-dict.7z",
                @"C:\project\PcapCompressor\all\all-dict.7z" };

            for (int k = 0; k < 10; k++)
            {
                for (int j = 0; j < testSourcePath.Length; j++)
                {
                    tbSourceFile.Text = testSourcePath[j];
                    tbOutputPath.Text = testOutputPath[j];

                    for (int i = 0; i < testThreadCount.Length; i++)
                    {
                        tbThreadCount.Text = testThreadCount[i].ToString();
                        btnSetThreadCount_Click(sender, e);

                        btnsave_Click(sender, e);

                    }
                }
            }
        }

        private void btnAutoRecoveryTest_Click(object sender, EventArgs e)
        {
            string[] testOutputPath = { @"C:\project\PcapCompressor\1m\1m-dict.7z",
                @"C:\project\PcapCompressor\10m\10m-dict.7z",
                @"C:\project\PcapCompressor\20m\20m-dict.7z",
                @"C:\project\PcapCompressor\30m\30m-dict.7z",
                @"C:\project\PcapCompressor\40m\40m-dict.7z",
                @"C:\project\PcapCompressor\50m\50m-dict.7z",
                @"C:\project\PcapCompressor\all\all-dict.7z" };

            string[] recoverFilePath = { @"C:\project\PcapCompressor\1m\1m-recovery.pcap",
                @"C:\project\PcapCompressor\10m\10m-recovery.pcap",
                @"C:\project\PcapCompressor\20m\20m-recovery.pcap",
                @"C:\project\PcapCompressor\30m\30m-recovery.pcap",
                @"C:\project\PcapCompressor\40m\40m-recovery.pcap",
                @"C:\project\PcapCompressor\50m\50m-recovery.pcap",
                @"C:\project\PcapCompressor\all\all-recovery.pcap" };

            for (int k = 0; k < 10; k++)
            {
                for (int i = 0; i < testOutputPath.Length; i++)
                {
                    var scaninfo = Recover.ReadDictionary(testOutputPath[i]);
                    var maxUsedAddress = scaninfo.r_sort_dict_IPAddress[0];
                    var minUsedAddress = scaninfo.r_sort_dict_IPAddress[scaninfo.r_sort_dict_IPAddress.Count - 1];
                    for (int j = 0; j < 2; j++)
                    {
                        var currentIP = j == 0 ? maxUsedAddress : minUsedAddress;
                        if (File.Exists(recoverFilePath[i]))
                        {
                            File.Delete(recoverFilePath[i]);
                        }
                        Stopwatch sw = new Stopwatch();
                        sw.Start();

                        var split = tbFindIP.Text.Split('.');
                        Exp.Recover.RecoverTargetPcap(testOutputPath[i], recoverFilePath[i], currentIP);
                        sw.Stop();


                        var ipstr = string.Format("{0}.{1}.{2}.{3}", currentIP[0], currentIP[1], currentIP[2], currentIP[3]);
                        Tools.Log.LogToFile("recovery, " + testOutputPath[i] + "," + (j == 0 ? "max" : "min") + "," + ipstr + "," + sw.ElapsedMilliseconds.ToString());
                    }

                }
            }

        }

        private void btnAutoAll_Click(object sender, EventArgs e)
        {
            btnAutoTest_Click(sender, e);
            btnAutoRecoveryTest_Click(sender, e);
        }

        private void btnPowershell_Click(object sender, EventArgs e)
        {
            tbPowershell.Text=PowerShellBuilder.Build(tbSourceFile.Text,1);
        }
    }
}
