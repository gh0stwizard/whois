using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Tokens;
using Whois.Logging;
using Whois.Net;
using Whois.Parsers;

namespace Whois.Servers
{
    public sealed class ArinServerLookup : WhoisServerLookupBase<NetworkResponse>
    {
        private const string Server = "whois.arin.net";
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();


        /// <summary>
        /// Creates a new instance of the ARIN Server Lookup
        /// </summary>
        public ArinServerLookup() : this(new TcpReader())
        {
        }

        public ArinServerLookup(ITcpReader tcpReader) : base(tcpReader)
        {
            ResponseType = typeof(NetworkResponse);
            Parser = new WhoisNetworkParser();
        }


        public override async Task<WhoisResponse> LookupAsync(WhoisRequest request)
        {
            var server = request.WhoisServer ?? Server;
            var content = await DownloadAsync(server, request);
            var result = Parser.Parse(server, content);

            if (result != null)
            {
                return result;
            }

            return new NetworkResponse { Content = content };
        }


        public override async Task<string> DownloadAsync(string url, WhoisRequest request)
        {
            var query = request.Query;
            if (!query.StartsWith("n ")) query = "n " + query;

            var content = await TcpReader.Read(url, 43, query, request.Encoding, request.TimeoutSeconds);

            Log.Debug("Lookup {0}: Downloaded {1:###,###,##0} byte(s) from {2}.", request.Query, content.Length, url);

            return content;
        }
    }
}
