﻿using System;
using System.Linq;
using System.Threading.Tasks;
using Tokens;
using Whois.Logging;
using Whois.Net;
using Whois.Parsers;
using Whois.Parsers.Fixups;

namespace Whois.Servers
{
    /// <summary>
    /// Class to lookup a WHOIS server for a TLD from IANA 
    /// </summary>
    public sealed class IanaServerLookup : WhoisServerLookupBase<DomainResponse>
    {
        private const string Server = "whois.iana.org";
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();

        /// <summary>
        /// Creates a new instance of the IANA Server Lookup
        /// </summary>
        public IanaServerLookup() : this(new TcpReader())
        {
        }

        public IanaServerLookup(ITcpReader tcpReader) : base(tcpReader)
        {
            ResponseType = typeof(DomainResponse);
            Parser = new WhoisDomainParser();
        }

        public override async Task<WhoisResponse> LookupAsync(WhoisRequest request)
        {
            var server = request.WhoisServer ?? Server;
            var content = await DownloadAsync(server, request);
            var result = Parser.Parse(server, content);

            if (result != null)
            {
                if (!request.HostName.IsIP && result.DomainName == null)
                    result.DomainName = new HostName(request.HostName.Tld);

                return result;
            }

            return new DomainResponse { Content = content };
        }

        public override async Task<string> DownloadAsync(string url, WhoisRequest request)
        {
            // TODO: Expose this & extend for other TLDs
            var query = request.Query;
            if (query.EndsWith("jp")) query += "/e";    // Return English .jp results

            var content = await TcpReader.Read(url, 43, query, request.Encoding, request.TimeoutSeconds);

            Log.Debug("Lookup {0}: Downloaded {1:###,###,##0} byte(s) from {2}.", request.Query, content.Length, url);

            return content;
        }
    }
}