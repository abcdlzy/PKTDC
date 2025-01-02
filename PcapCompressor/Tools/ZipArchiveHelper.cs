using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.Tools
{
    internal class ZipArchiveHelper
    {
        public static void AddToZipArchive(string zipFilePath, string entryName, HugeMemoryStream memoryStream)
        {
            using (var archive = ZipFile.Open(zipFilePath, ZipArchiveMode.Update))
            {
                var entry = archive.CreateEntry(entryName);
                using (var stream = entry.Open())
                {
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    memoryStream.CopyTo(stream);
                }
            }
        }

        public static void AddToZipArchive(string zipFilePath, string entryName, byte[] bytes)
        {
            using (var archive = ZipFile.Open(zipFilePath, ZipArchiveMode.Update))
            {
                var entry = archive.CreateEntry(entryName);
                using (var stream = entry.Open())
                {
                    stream.Write(bytes, 0, bytes.Length);
                }
            }
        }




        public static HugeMemoryStream ReadFileFromZipArchive(string zipFilePath, string entryName)
        {
            using (var archive = ZipFile.OpenRead(zipFilePath))
            {
                var entry = archive.GetEntry(entryName);
                if (entry == null)
                {
                    throw new FileNotFoundException($"The specified file '{entryName}' was not found in the archive.");
                }
                using (var stream = entry.Open())
                {
                    var memoryStream = new HugeMemoryStream();
                    stream.CopyTo(memoryStream);
                    return memoryStream;
                }
            }
        }

        public static HugeMemoryStream ReadFileFromZipArchive(string zipFilePath, string entryName, long offset, int length)
        {
            using (var archive = ZipFile.OpenRead(zipFilePath))
            {
                var entry = archive.GetEntry(entryName);
                if (entry == null)
                {
                    throw new FileNotFoundException($"The specified file '{entryName}' was not found in the archive.");
                }
                using (var stream = entry.Open())
                {
                    stream.Seek(offset, SeekOrigin.Begin);
                    var buffer = new byte[length];
                    stream.Read(buffer, 0, length);
                    var memoryStream = new HugeMemoryStream(buffer);
                    return memoryStream;
                }
            }
        }

        /*
        public static bool TryReadFileFromZipArchive(ZipArchive archive, string fileName, long offset, int length, out HugeMemoryStream stream)
        {
            stream = null;

            ZipArchiveEntry entry = archive.GetEntry(fileName);
            if (!ValidateOffsetAndLength(entry, offset, length))
            {
                return false;
            }

            stream = new HugeMemoryStream(length);
            using (Stream entryStream = entry.Open())
            {
                entryStream.Seek(offset, SeekOrigin.Begin);
                entryStream.CopyTo(stream, length);
            }

            return true;
        }
        */

        private static bool ValidateOffsetAndLength(ZipArchiveEntry entry, long offset, int length)
        {
            if (entry == null || offset < 0 || offset >= entry.Length || length < 0)
            {
                return false;
            }

            length = Math.Min(length, (int)(entry.Length - offset));

            return true;
        }


    }
}
