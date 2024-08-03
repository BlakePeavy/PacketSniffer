using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    public class IPHeader
    {
        public byte Version;
        public byte HeaderLength;
        public byte TypeOfService;
        public ushort TotalLength;
        public ushort Identification;
        public ushort FlagsAndOffset;
        public byte TTL;
        public byte Protocol;
        public ushort Checksum;
        public IPAddress SourceAddress;
        public IPAddress DestinationAddress;

        public IPHeader(byte[] buffer, int length)
        {
            Version = (byte)(buffer[0] >> 4);
            HeaderLength = (byte)(buffer[0] & 0x0F);
            TypeOfService = buffer[1];
            TotalLength = BitConverter.ToUInt16(new byte[] { buffer[3], buffer[2] }, 0);
            Identification = BitConverter.ToUInt16(new byte[] { buffer[5], buffer[4] }, 0);
            FlagsAndOffset = BitConverter.ToUInt16(new byte[] { buffer[7], buffer[6] }, 0);
            TTL = buffer[8];
            Protocol = buffer[9];
            Checksum = BitConverter.ToUInt16(new byte[] { buffer[11], buffer[10] }, 0);
            SourceAddress = new IPAddress(BitConverter.ToUInt32(buffer, 12));
            DestinationAddress = new IPAddress(BitConverter.ToUInt32(buffer, 16));
        }

        public override string ToString()
        {
            return $"Version: {Version}, Header Length: {HeaderLength * 4}, Total Length: {TotalLength}, " +
                   $"Source: {SourceAddress}, Destination: {DestinationAddress}, Protocol: {Protocol}";
        }
    }

}
