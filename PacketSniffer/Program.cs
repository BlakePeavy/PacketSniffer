using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;


namespace PacketSniffer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // List all IP addresses on adapter
                ListAvailableIPAddresses();

                // Prompt user to input an IP address for listening
                Console.Write("Enter the IP address to listen on: ");
                string inputIpAddress = Console.ReadLine();

                // Validate the address
                if (ValidateIPAddress(inputIpAddress))
                {
                    PacketSniffer sniffer = new PacketSniffer();

                    // Start sniffing on a thread
                    Thread sniffingThread = new Thread(() => sniffer.StartSniffing(inputIpAddress));
                    sniffingThread.Start();

                    Console.WriteLine("Press Enter to stop sniffing...");
                    Console.ReadLine();

                    // Stop sniffing and wait for the thread to finish
                    sniffer.StopSniffing();
                    sniffingThread.Join();

                    Console.WriteLine("Sniffing stopped.");
                }
                else
                {
                    // Print error
                    Console.WriteLine("Invalid IP address. Please enter a valid IP address from the list.");
                }
            }
            catch (Exception ex)
            {
                // Print error
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }

        /// <summary>
        /// Lists all available addresses on machine
        /// </summary>
        static void ListAvailableIPAddresses()
        {
            Console.WriteLine("IP addresses found:");

            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        Console.WriteLine(ip.Address.ToString());
                    }
                }
            }
        }


        /// <summary>
        /// Validate users input
        /// </summary>
        /// <param name="ipAddress">User entered address</param>
        /// <returns>True - Address can be parsed or False - Address cannot be parsed</returns>
        static bool ValidateIPAddress(string ipAddress)
        {
            if (IPAddress.TryParse(ipAddress, out IPAddress parsedAddress))
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork && ip.Address.Equals(parsedAddress))
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
    }
}
