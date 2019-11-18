using NUnit.Framework;
using Whois.Parsers.Fixups;

namespace Whois.Parsers
{
    [TestFixture]
    public class WhoisParserTests
    {
        private WhoisDomainParser parser;
        private SampleReader sampleReader;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisDomainParser();
            sampleReader = new SampleReader();

            parser.Matcher.RegisterTransformer<CleanDomainStatusTransformer>();
            parser.Matcher.RegisterTransformer<ToHostNameTransformer>();

            // Register default FixUps
            parser.FixUps.Add(new MultipleContactFixup());
            parser.FixUps.Add(new WhoisIsocOrgIlFixup());
        }

        [Test]
        public void TestParseDomainNameWhois()
        {
            var sample = sampleReader.Read("capetown-whois.registry.net.za", "capetown", "found.txt");

            var result = parser.Parse("capetown-whois.registry.net.za", sample);

            Assert.IsNotNull(result);
            Assert.AreEqual("registry.capetown", result.DomainName.ToString());
            Assert.AreEqual(WhoisStatus.Found, result.Status);
            Assert.AreEqual(2, parser.Templates.Names.Count);
        }

        [Test]
        public void TestParseDomainNameWhoisDoesNotRegisterTemplateTwice()
        {
            var sample = sampleReader.Read("capetown-whois.registry.net.za", "capetown", "found.txt");

            parser.Parse("capetown-whois.registry.net.za", sample);
            parser.Parse("capetown-whois.registry.net.za", sample);

            Assert.AreEqual(2, parser.Templates.Names.Count);
        }
    }
}
