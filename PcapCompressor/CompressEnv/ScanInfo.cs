using PcapCompressor.Tools;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PcapCompressor.CompressEnv
{
    internal class ScanInfo
    {
        //pcap header
        public ConcurrentDictionary<byte[], int> dict_PKTLength = new ConcurrentDictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<byte[], int> sort_dict_PKTLength = new Dictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<int,byte[]> r_sort_dict_PKTLength = new Dictionary<int,byte[]>();

        //ethernet
        //mac
        public ConcurrentDictionary<byte[],int> dict_Ethernet_MAC = new ConcurrentDictionary<byte[],int>(new ByteArrayEqualityComparer());
        public Dictionary<byte[], int> sort_dict_Ethernet_MAC = new Dictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<int, byte[]> r_sort_dict_Ethernet_MAC = new Dictionary<int, byte[]>();

        //Type
        public ConcurrentDictionary<byte[], int> dict_Ethernet_Type = new ConcurrentDictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<byte[], int> sort_dict_Ethernet_Type = new Dictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<int, byte[]> r_sort_dict_Ethernet_Type = new Dictionary<int, byte[]>();

        //ip
        //protocol
        public ConcurrentDictionary<byte[], int> dict_Protocol = new ConcurrentDictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<byte[], int> sort_dict_Protocol = new Dictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<int, byte[]> r_sort_dict_Protocol = new Dictionary<int, byte[]>();

        public ConcurrentDictionary<byte[], int> dict_IPAddress = new ConcurrentDictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<byte[], int> sort_dict_IPAddress = new Dictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<int, byte[]> r_sort_dict_IPAddress = new Dictionary<int, byte[]>();

        /*
        //IPv4 address
        public ConcurrentDictionary<byte[], int> dict_IPv4_Address = new ConcurrentDictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<byte[], int> sort_dict_IPv4_Address = new Dictionary<byte[], int>(new ByteArrayEqualityComparer());

        //IPv6 address
        public ConcurrentDictionary<byte[], int> dict_IPv6_Address = new ConcurrentDictionary<byte[], int>(new ByteArrayEqualityComparer());
        public Dictionary<byte[], int> sort_dict_IPv6_Address = new Dictionary<byte[], int>(new ByteArrayEqualityComparer());
        */
    }
}
