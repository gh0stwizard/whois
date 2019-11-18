using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using Whois.Net;

namespace Whois.Servers
{
    public class WhoisServerSelector
    {
        private readonly ConcurrentDictionary<string, IWhoisServerLookup> cache =
            new ConcurrentDictionary<string, IWhoisServerLookup>();
        private ITcpReader _tcpReader;


        private IWhoisServerLookup _default;
        public IWhoisServerLookup Default
        {
            get
            {
                if (_default == null)
                    _default = new IanaServerLookup(_tcpReader);
                return _default;
            }
        }


        public WhoisServerSelector(ITcpReader tcpReader)
        {
            _tcpReader = tcpReader;
        }


        public IWhoisServerLookup Find(string server)
        {
            switch (server)
            {
                case "whois.arin.net":
                    return cache.GetOrAdd(server, a => new ArinServerLookup(_tcpReader));

                default:
                    return Default;
            }
        }


        public IWhoisServerLookup Find(HostName hostName) => Find(hostName.Value);
    }
}
