using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SevenZip;
using SevenZip.Sdk;

namespace PcapCompressor.Tools
{
    internal class SevenZipArchiveHelper
    {
        static Dictionary<string, Stream> streamDict=new Dictionary<string, Stream>();

        public static void AddToZipArchive(string zipFilePath, string entryName, HugeMemoryStream memoryStream)
        {
            //memoryStream.Capacity=(int)memoryStream.Length;
            memoryStream.Seek(0, SeekOrigin.Begin);
            streamDict.Add(entryName, memoryStream);
            
        }

        public static void DoCompressToZipArchive(string zipFilePath)
        {
            SevenZip.SevenZipCompressor.SetLibraryPath(Global.sevenZipDLLPath);

            using (FileStream ostream = new FileStream(zipFilePath, FileMode.Create, FileAccess.Write))
            {
                SevenZipCompressor compressor = new SevenZipCompressor();
                compressor.CompressionLevel = SevenZip.CompressionLevel.Ultra;
                compressor.CompressionMethod = CompressionMethod.Lzma2;
                compressor.CompressStreamDictionary(streamDict, ostream);          
            }
            streamDict.Clear();
            ;
        }



        public static HugeMemoryStream ReadFileFromZipArchive(string zipFilePath, string entryName)
        {
            SevenZip.SevenZipCompressor.SetLibraryPath(Global.sevenZipDLLPath);
            using (var archive = new SevenZipExtractor(zipFilePath))
            {
                var entry = archive.ArchiveFileData.FirstOrDefault(x => x.FileName == entryName);
                if (entry == null)
                {
                    throw new ArgumentException("Entry not found in archive");
                }
                var stream = new HugeMemoryStream();
                archive.ExtractFile(entry.Index, stream);
                stream.Seek(0, SeekOrigin.Begin);
                return stream;
            }
        }


    }
}
