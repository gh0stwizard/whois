using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Tokens;
using Whois.Net;
using Whois.Parsers;

namespace Whois.Servers
{
    public class WhoisServerLookupBase<T> : IWhoisServerLookup
        where T: WhoisResponse, new()
    {
        /// <summary>
        /// TBA
        /// </summary>
        public WhoisParserBase<T> Parser { get; protected set; }

        /// <summary>
        /// Type of server response
        /// </summary>
        public Type ResponseType = typeof(T);

        /// <summary>
        /// The <see cref="ITcpReader"/> to use for network requests
        /// </summary>
        public ITcpReader TcpReader { get; set; }

        /// <summary>
        /// Creates a new instance of the IANA Server Lookup
        /// </summary>
        public WhoisServerLookupBase() : this(new TcpReader())
        {
        }

        public WhoisServerLookupBase(ITcpReader tcpReader)
        {
            TcpReader = tcpReader;
        }

        public virtual WhoisResponse Lookup(WhoisRequest request)
        {
            return AsyncHelper.RunSync(() => LookupAsync(request));
        }

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        public virtual async Task<WhoisResponse> LookupAsync(WhoisRequest request)
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
        {
            throw new NotImplementedException();
        }

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        public virtual async Task<string> DownloadAsync(string url, WhoisRequest request)
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
        {
            throw new NotImplementedException();
        }

        public void Dispose() => TcpReader?.Dispose();
    }
}
