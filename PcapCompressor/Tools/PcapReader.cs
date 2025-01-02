using SharpPcap.LibPcap;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading.Tasks;
using static System.Windows.Forms.AxHost;
using System.Runtime.InteropServices;
using System.Security;

namespace PcapCompressor.Tools
{
    [SuppressUnmanagedCodeSecurity]
    internal class PcapReader
    {
        private const string PCAP_DLL = "wpcap";
        [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
        internal extern static int pcap_next_ex(PcapHandle /* pcap_t* */ adaptHandle, ref IntPtr /* **pkt_header */ header, ref IntPtr data);


        /// <summary>
        /// Retrieve the next packet data
        /// </summary>
        /// <param name="e">Structure to hold the packet data info</param>
        /// <returns>Status of the operation</returns>
        public static GetPacketStatus GetNextPacket(PcapHandle pcapHandle,out IntPtr header,out IntPtr data)
        {
            //Pointer to a packet info struct
            header = IntPtr.Zero;

            //Pointer to a packet struct
            data = IntPtr.Zero;

            int res;

            unsafe
            {
                //Get a packet from npcap
                res = pcap_next_ex(pcapHandle, ref header, ref data);
            }
            ;
            return (GetPacketStatus)res;
        }
    }
}
