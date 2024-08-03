using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer
{
    public class PacketSniffer
    {
        private Socket _socket;

        /// <summary>
        /// Flag to determine if sniffing is running
        /// </summary>
        private bool _isSniffing;

        /// <summary>
        /// Start sniffing process
        /// </summary>
        /// <param name="ipAddress">Selected IP Address</param>
        public void StartSniffing(string ipAddress)
        {
            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                _socket.Bind(new IPEndPoint(IPAddress.Parse(ipAddress), 0));
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                byte[] optionIn = new byte[] { 1, 0, 0, 0 };
                byte[] optionOut = new byte[4];
                _socket.IOControl(IOControlCode.ReceiveAll, optionIn, optionOut);

                _isSniffing = true;

                StartReceiving();

                while (_isSniffing)
                {
                    // Adjusted to reduce lag
                    Thread.Sleep(1000);
                }
            }
            catch (SocketException ex)
            {
                // Print error
                Console.WriteLine($"Socket error: {ex.Message}");
            }
            catch (Exception ex)
            {
                // Print error
                Console.WriteLine($"An error occurred while sniffing: {ex.Message}");
            }
        }

        /// <summary>
        /// Stop the sniffing function
        /// </summary>
        public void StopSniffing()
        {
            _isSniffing = false;
            if (_socket != null)
            {
                _socket.Close();
            }
        }

        /// <summary>
        /// Start receiving packets
        /// </summary>
        private void StartReceiving()
        {
            try
            {
                // Start with a large buffer
                byte[] buffer = new byte[65535];
                _socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(OnReceive), buffer);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting receive: {ex.Message}");
            }
        }

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                if (!_isSniffing) return;

                byte[] buffer = (byte[])ar.AsyncState;
                int received = _socket.EndReceive(ar);

                if (received > 0)
                {
                    // Process only the part of the buffer that contains the packet data
                    byte[] packetData = new byte[received];
                    Array.Copy(buffer, 0, packetData, 0, received);

                    IPHeader ipHeader = new IPHeader(packetData, received);
                    Console.WriteLine(ipHeader.ToString());
                }

                // Start receiving the next packet
                StartReceiving();
            }
            catch (SocketException ex)
            {
                // Print error
                Console.WriteLine($"Socket receive error: {ex.Message}");
            }
            catch (Exception ex)
            {
                // Print error
                Console.WriteLine($"Error in OnReceive: {ex.Message}");
            }
        }
    }
}
