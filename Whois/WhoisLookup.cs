using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Tokens.Extensions;
using Whois.Logging;
using Whois.Net;
using Whois.Parsers;
using Whois.Servers;

namespace Whois
{
    /// <summary>
    /// Looks up WHOIS information
    /// </summary>
    public class WhoisLookup : IWhoisLookup
    {
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();
        public WhoisServerSelector ServerSelector;

        /// <summary>
        /// The default <see cref="WhoisOptions"/> to use for this instance
        /// </summary>
        public WhoisOptions Options { get; set; }


        public IWhoisServerLookup ServerLookup { get; set; }

        /// <summary>
        /// The TCP reader that performs the network requests
        /// </summary>
        public ITcpReader TcpReader { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class with the default options
        /// </summary>
        public WhoisLookup() : this(WhoisOptions.Defaults.Clone())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class with the given <see cref="WhoisOptions"/>.
        /// </summary>
        public WhoisLookup(WhoisOptions options)
        {
            Options = options;
            TcpReader = new TcpReader();
            ServerSelector = new WhoisServerSelector(TcpReader);
            ServerLookup = ServerSelector.Default;
        }

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain.
        /// </summary>
        public WhoisResponse Lookup(string domain)
        {
            return AsyncHelper.RunSync(() => LookupAsync(domain));
        }

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain with the given encoding.
        /// </summary>
        public WhoisResponse Lookup(string domain, Encoding encoding)
        {
            return AsyncHelper.RunSync(() => LookupAsync(domain, encoding));
        }

        /// <summary>
        /// Performs a WHOIS lookup for the given request.
        /// </summary>
        public WhoisResponse Lookup(WhoisRequest request)
        {
            return AsyncHelper.RunSync(() => LookupAsync(request));
        }

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain.
        /// </summary>
        public Task<WhoisResponse> LookupAsync(string domain)
        {
            return LookupAsync(domain, Options.Encoding);
        }

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain with the given encoding.
        /// </summary>
        public Task<WhoisResponse> LookupAsync(string domain, Encoding encoding)
        {
            return LookupAsync(new WhoisRequest(domain)
            {
                Encoding = encoding,
                TimeoutSeconds = Options.TimeoutSeconds,
                FollowReferrer = Options.FollowReferrer
            });
        }

        /// <summary>
        /// Performs a WHOIS lookup for the given request.
        /// </summary>
        public async Task<WhoisResponse> LookupAsync(WhoisRequest request)
        {
            Log.Debug("Looking up WHOIS response for: {0}", request.HostName.Value);

            // Set our starting point
            WhoisResponse response;
            if (string.IsNullOrEmpty(request.WhoisServer))
            {
                // Lookup root WHOIS server for the TLD
                response = await ServerLookup.LookupAsync(request);
            }
            else
            {
                // Use the given WHOIS server
                response = WhoisResponse.WithServerUrl(request.WhoisServer);
            }

            // Main loop: download & parse WHOIS data and follow the referrer chain
            HostName whoisServer = null;
            while (response?.WhoisServer != null)
            {
                if (Options.IgnoredWhoisServers.Contains(response.WhoisServer.Value)
                    || (!request.HostName.IsIP && request.HostName.IsTld))
                    break;

                if (whoisServer != response.WhoisServer)
                {
                    whoisServer = response.WhoisServer;
                    ServerLookup = ServerSelector.Find(whoisServer);
                    request.WhoisServer = response.WhoisServer.Value;
                }

                var parsed = await ServerLookup.LookupAsync(request);

                // Build referrer chain
                response = response.Chain(parsed);

                // Check for referral loop
                if (request.FollowReferrer == false || response.SeenServer(response.WhoisServer))
                    break;
            }

            return response;
        }

        public void Dispose()
        {
            TcpReader?.Dispose();
        }
    }
}