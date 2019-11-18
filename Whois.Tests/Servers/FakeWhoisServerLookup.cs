using System.Threading.Tasks;

namespace Whois.Servers
{
    /// <summary>
    /// Fake class used for testing.
    /// </summary>
    internal class FakeWhoisServerLookup : WhoisServerLookupBase<DomainResponse>
    {
        public override WhoisResponse Lookup(WhoisRequest request)
        {
            return new DomainResponse
            {
                DomainName = new HostName("com"), 
                Registrar = new Registrar
                {
                    WhoisServer = new HostName("test.whois.com")
                }
            };
        }

        public override Task<WhoisResponse> LookupAsync(WhoisRequest request)
        {
            return Task.FromResult(Lookup(request));
        }

        public override Task<string> DownloadAsync(string url, WhoisRequest request)
        {
            throw new System.NotImplementedException();
        }
    }
}
