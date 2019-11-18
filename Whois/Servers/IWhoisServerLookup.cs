using System;
using System.Threading.Tasks;

namespace Whois.Servers
{
    /// <summary>
    /// Interface to lookup the appropriate root WHOIS server for a given request.
    /// </summary>
    public interface IWhoisServerLookup : IDisposable
    {
        /// <summary>
        /// Lookups the root WHOIS server for the specified request.
        /// </summary>
        WhoisResponse Lookup(WhoisRequest request);

        /// <summary>
        /// Lookups the root WHOIS server for the specified request.
        /// </summary>
        Task<WhoisResponse> LookupAsync(WhoisRequest request);

        /// <summary>
        /// Download result from specified WHOIS server URL and request options.
        /// </summary>
        /// <param name="url">WHOIS Server</param>
        /// <param name="request">Request options, <see cref="WhoisRequest"/>.</param>
        /// <returns>Content</returns>
        Task<string> DownloadAsync(string url, WhoisRequest request);
    }
}