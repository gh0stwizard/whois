using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Whois.Parsers.Fixups;

namespace Whois.Parsers
{
    public sealed class WhoisDomainParser : WhoisParserBase<DomainResponse>
    {
        public WhoisDomainParser() : base()
        {
            // Register default transformers
            Matcher.RegisterTransformer<CleanDomainStatusTransformer>();
            Matcher.RegisterTransformer<ToHostNameTransformer>();

            // Register default FixUps
            FixUps.Add(new MultipleContactFixup());
            FixUps.Add(new WhoisIsocOrgIlFixup());
        }


        public new DomainResponse Parse(string whoisServer, string content)
        {
            var result = base.Parse(whoisServer, content);

            if (result != null)
            {
                result.Status = WhoisStatusParser.Parse(whoisServer, result.DomainStatus.FirstOrDefault(), result.Status);
            }

            return result;
        }
    }
}
