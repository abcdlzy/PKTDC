using PcapCompressor.CompressEnv;
using PcapCompressor.Exp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.Tools
{
    public static class PowerShellBuilder
    {
        public static string Build(string filepath, int repeatCount)
        {
            var filename = Path.GetFileNameWithoutExtension(filepath);

            var pktPositionList = PcapParser.PreRead(filepath);
            PcapParser.ParallelPacketParser(filepath, Global.thread_FileCount, pktPositionList);

            var scaninfoRSortDictIPaddress= PcapParser.scanInfo.sort_dict_IPAddress.ToDictionary(pair => pair.Value, pair => pair.Key);

            //var scaninfo = Recover.ReadDictionary(filepath);
            var maxUsedAddress = new IPAddress(scaninfoRSortDictIPaddress[0]).ToString();
            var minUsedAddress = new IPAddress(scaninfoRSortDictIPaddress[scaninfoRSortDictIPaddress.Count - 1]).ToString();
            var extNames = new[] { "zip", "rar", "7z", "sz", "gz" };

            var sb = new StringBuilder();

            for (int i = 1; i <= repeatCount; i++)
            {
                AddCleanupCommands(sb, filename, extNames);
                AddCompressionCommands(sb, filename, i);

                foreach (var extName in extNames)
                {
                    AddRecoveryCommands(sb, extName, filename, maxUsedAddress, minUsedAddress, i);
                }
            }

            return sb.ToString();
        }

        private static void AddCleanupCommands(StringBuilder sb, string filename, string[] extNames)
        {
            foreach (var extName in extNames)
            {
                if (extName == "sz" || extName == "gz")
                {
                    sb.AppendLine($"del .\\{filename}-{extName}.pcap -ErrorAction SilentlyContinue");
                    sb.AppendLine($"del .\\{filename}-{extName}-min.pcap -ErrorAction SilentlyContinue");
                    sb.AppendLine($"del .\\{filename}-{extName}.pcap.{extName} -ErrorAction SilentlyContinue");
                    sb.AppendLine($"del .\\{filename}-{extName}-min.pcap.{extName} -ErrorAction SilentlyContinue");
                }
                else
                {
                    sb.AppendLine($"del .\\{filename}.{extName} -ErrorAction SilentlyContinue");
                }
            }
            sb.AppendLine("del .\\tsharkout.pcap -ErrorAction SilentlyContinue");
        }

        private static void AddCompressionCommands(StringBuilder sb, string filename, int batchNumber)
        {
            AddCompressionCommand(sb, filename, "zip", "zip -9 -q {0}.zip {0}.pcap", $"Compression-Zip-Batch-{batchNumber}", "zip", batchNumber);
            AddCompressionCommand(sb, filename, "rar", "& 'C:\\Program Files\\WinRAR\\Rar.exe' a -m5 {0}.rar {0}.pcap", $"Compression-Rar-Batch-{batchNumber}", "WinRAR", batchNumber);
            AddCompressionCommand(sb, filename, "7z", "& 'C:\\Program Files\\7-Zip\\7z.exe' a {0}.7z {0}.pcap -y -mmt12 -mx9", $"Compression-7z-Batch-{batchNumber}", "7z", batchNumber);
            AddCompressionCommand(sb, filename, "sz", "copy {0}.pcap {0}-sz.pcap\n& 'C:\\snzip-1.0.5\\snzip.exe' {0}-sz.pcap", $"Compression-Sz-Batch-{batchNumber}", "snzip", batchNumber, true);
            AddCompressionCommand(sb, filename, "gz", "copy {0}.pcap {0}-gz.pcap\n& 'C:\\gzip-1.3.12\\bin\\gzip.exe' {0}-gz.pcap", $"Compression-Gz-Batch-{batchNumber}", "gzip", batchNumber, true);
        }

        private static void AddCompressionCommand(StringBuilder sb, string filename, string ext, string command, string batchName, string programName, int batchNumber, bool hasExtraSteps = false)
        {
            sb.AppendLine(ClearPerfSettingCommand());
            sb.AppendLine(UpdatePerfSettingCommand($"{batchName}-PowerShell", "powershell", batchNumber));
            sb.AppendLine(UpdatePerfSettingCommand(batchName, programName, batchNumber));
            sb.AppendLine("$start = Get-Date");
            sb.AppendFormat(command, filename);
            sb.AppendLine();
            sb.AppendLine("$end = Get-Date");
            sb.AppendFormat("Write-Host -ForegroundColor Red ('compression==>,{0},{1}, compress,' + ($end - $start).TotalSeconds)", filename, ext);
            sb.AppendLine();

            if (hasExtraSteps)
            {
                if (ext == "sz")
                {
                    sb.AppendFormat("copy {0}-sz.pcap.sz {0}-sz-min.pcap.sz", filename);
                    sb.AppendLine();
                }
                else if (ext == "gz")
                {
                    sb.AppendFormat("copy {0}-gz.pcap.gz {0}-gz-min.pcap.gz", filename);
                    sb.AppendLine();
                }
            }
        }

        private static void AddRecoveryCommands(StringBuilder sb, string extName, string filename, string maxUsedAddress, string minUsedAddress, int batchNumber)
        {
            var currentUnzipExe = GetUnzipExePath(extName);

            AddIndividualRecoveryCommands(sb, extName, filename, maxUsedAddress, currentUnzipExe, batchNumber, isMin: false);
            AddIndividualRecoveryCommands(sb, extName, filename, minUsedAddress, currentUnzipExe, batchNumber, isMin: true);
        }

        private static void AddIndividualRecoveryCommands(StringBuilder sb, string extName, string filename, string ipAddress, string currentUnzipExe, int batchNumber, bool isMin)
        {
            var minSuffix = isMin ? "-min" : string.Empty;
            var extSuffix = extName == "sz" || extName == "gz" ? $"-{extName}{minSuffix}" : string.Empty;
            var batchName = isMin ? $"Recovery-{extName}-MinBatch-{batchNumber}" : $"Recovery-{extName}-MaxBatch-{batchNumber}";

            sb.AppendLine(ClearPerfSettingCommand());
            sb.AppendLine(UpdatePerfSettingCommand($"Recovery-PowerShell-{minSuffix}Batch-{batchNumber}", "powershell", batchNumber));
            sb.AppendLine(UpdatePerfSettingCommand(batchName, Path.GetFileNameWithoutExtension(currentUnzipExe), batchNumber));
            sb.AppendLine(UpdatePerfSettingCommand($"Recovery-Tshark-{extName}-{minSuffix}Batch-{batchNumber}", "tshark", batchNumber));
            sb.AppendLine($"del .\\{filename}{extSuffix}.pcap -ErrorAction SilentlyContinue");
            sb.AppendLine("del .\\tsharkout.pcap -ErrorAction SilentlyContinue");
            sb.AppendLine("$start = Get-Date");

            if (extName == "sz" || extName == "gz")
            {
                sb.AppendFormat("& '{0}' -d .\\{1}{2}.pcap.{3}", currentUnzipExe, filename, extSuffix, extName);
                sb.AppendLine();
            }
            else
            {
                sb.AppendFormat("& '{0}' e {1}.{2} {1}.pcap", currentUnzipExe, filename, extName);
                sb.AppendLine();
            }

            sb.AppendFormat("& 'C:\\Program Files\\Wireshark\\tshark.exe' -r {0}{1}.pcap -w tsharkout.pcap \"{3}.src=={2}||{3}.dst=={2}\"", filename, extSuffix, ipAddress,ipAddress.Contains(":")?"ipv6":"ip");
            sb.AppendLine();
            sb.AppendLine("$end = Get-Date");
            sb.AppendFormat("Write-Host -ForegroundColor Red ('Recovery==>,{0},{1}, {2}, {3} ,' + ($end - $start).TotalSeconds)", filename, extName, isMin ? "Min" : "Max", ipAddress);
            sb.AppendLine();
            sb.AppendFormat("\"{0},{1},{2},{3},{4}\" | Add-Content -Path recovery_times.csv", filename, extName, isMin ? "Min" : "Max", ipAddress, "$($end - $start).TotalSeconds");
            sb.AppendLine();
        }

        private static string GetUnzipExePath(string extName)
        {
            return extName switch
            {
                "zip" => @"C:\\Program Files\\WinRAR\\WinRAR.exe",
                "rar" => @"C:\\Program Files\\WinRAR\\WinRAR.exe",
                "7z" => @"C:\\Program Files\\7-Zip\\7z.exe",
                "sz" => @"C:\\snzip-1.0.5\\snzip.exe",
                "gz" => @"C:\\gzip-1.3.12\\bin\\gzip.exe",
                _ => throw new ArgumentException("Unsupported extension", nameof(extName)),
            };
        }

        private static string ClearPerfSettingCommand()
        {
            return "\"\" | Set-Content -Path C:\\perfsetting.conf";
        }

        private static string UpdatePerfSettingCommand(string batchName, string programName, int batchNumber)
        {
            var commands = new List<string>
            {
                $"$retryCount = 0",
                $"$maxRetries = 10",
                $"$retryDelay = 0.1",  // Delay in seconds (100 milliseconds)
                $"do {{",
                $"    try {{",
                $"        \"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),{batchName},{programName}\" | Add-Content -Path C:\\perfsetting.conf",
                $"        $success = $true",
                $"    }} catch [System.IO.IOException] {{",
                $"        $retryCount++",
                $"        if ($retryCount -ge $maxRetries) {{ throw }}",
                $"        Start-Sleep -Seconds $retryDelay",
                $"    }}",
                $"}} while (-not $success)"
            };

            if (programName == "WinRAR")
            {
                commands.AddRange(new List<string>
                {
                    $"$retryCount = 0",
                    $"do {{",
                    $"    try {{",
                    $"        \"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),{batchName},Rar\" | Add-Content -Path C:\\perfsetting.conf",
                    $"        $success = $true",
                    $"    }} catch [System.IO.IOException] {{",
                    $"        $retryCount++",
                    $"        if ($retryCount -ge $maxRetries) {{ throw }}",
                    $"        Start-Sleep -Seconds $retryDelay",
                    $"    }}",
                    $"}} while (-not $success)"
                });
            }

            return string.Join(Environment.NewLine, commands);
        }
    }
}
