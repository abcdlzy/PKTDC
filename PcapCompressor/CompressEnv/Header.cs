using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.CompressEnv
{
    internal class Header
    {
        public byte[] pktlen;
        public byte[] MAC;
        public byte[] type;

        public byte[] protocol;
        public byte[] IPAddress_dst;
        public byte[] IPAddress_src;
        /*
        public byte[] IPv4Address_dst;
        public byte[] IPv4Address_src;
        public byte[] IPv6Address_dst;
        public byte[] IPv6Address_src;
        */
    }
}
