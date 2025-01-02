using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.CompressEnv
{
    internal class HeaderCollection
    {
        public byte[] pcapHeader;
        public bool isLittleEndian;

        public List<Header> headerList=new List<Header>();
    }
}
