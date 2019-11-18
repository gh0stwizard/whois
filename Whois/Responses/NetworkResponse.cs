using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Text;

namespace Whois
{
    public class NetworkResponse : WhoisResponse
    {
        public NetworkResponse()
        {
            ResponseType = typeof(NetworkResponse);
        }


        /// <summary>
        /// Returns networks for queried hostname
        /// </summary>
        public IPAddressCollection Networks { get; }
    }
}
