using System.Collections.Generic;
using System.Linq;
using Tokens;
using Tokens.Transformers;
using Tokens.Validators;
using Whois.Parsers.Fixups;

namespace Whois.Parsers
{
    /// <summary>
    /// Parser to turn WHOIS server responses into <see cref="WhoisResponse"/>
    /// objects.
    /// </summary>
    public class WhoisParserBase<Tresponse>
        where Tresponse : WhoisResponse, new()
    {
        private const string GenericTemplateTag = "catch-all";

        public TokenMatcher Matcher { get; internal set; }
        public ResourceReader Reader { get; internal set; }

        /// <summary>
        /// Creates a new instance of the <see cref="WhoisParser"/> class.
        /// </summary>
        public WhoisParserBase()
        {
            Matcher = new TokenMatcher();
            Reader = new ResourceReader();
            FixUps = new List<IFixup<Tresponse>>();
        }

        /// <summary>
        /// Contains the registered templates
        /// </summary>
        public TemplateCollection Templates => Matcher.Templates;

        /// <summary>
        /// Template Fixups
        /// </summary>
        public IList<IFixup<Tresponse>> FixUps { get; } = new List<IFixup<Tresponse>>();

        /// <summary>
        /// Parses the WHOIS server response for the given server and TLD.
        /// </summary>
        public Tresponse Parse(string whoisServer, string content)
        {
            LoadServerTemplates(whoisServer);

            var result = Matcher.Match<Tresponse>(content, new[] { whoisServer });

            var match = result.BestMatch;

            if (match == null)
            {
                LoadServerGenericTemplates();

                match = Matcher
                    .Match<Tresponse>(content, new[] { "catch-all" })
                    .BestMatch;
            }

            if (match == null)
                return null;

            // Perform extended processing on parsed data
            // via FixUps.
            foreach (var fixup in FixUps)
            {
                if (fixup.CanFixup(match))
                {
                    fixup.Fixup(match);
                }
            }

            var value = match.Value;

            value.Content = content;
            value.FieldsParsed = match.Tokens.Matches.Count;
            value.ParsingErrors = match.Exceptions.Count;
            value.TemplateName = match.Template.Name;

            return value;
        }

        public void AddTemplate(string content, string name)
        {
            Matcher.RegisterTemplate(content, name);
        }

        public void ClearTemplates()
        {
            Matcher.Templates.Clear();
        }

        public void RegisterValidator<T>() where T : ITokenValidator
        {
            Matcher.RegisterValidator<T>();
        }

        public void RegisterTransformer<T>() where T : ITokenTransformer
        {
            Matcher.RegisterTransformer<T>();
        }

        private void LoadServerTemplates(string whoisServer)
        {
            // Check templates for this server/tld not already loaded
            var loaded = Templates.ContainsTag(whoisServer);

            if (loaded) return;

            var templateNames = Reader.GetNames(whoisServer);

            foreach (var templateName in templateNames)
            {
                var content = Reader.GetContent(templateName);

                Matcher.RegisterTemplate(content);
            }
        }

        protected virtual void LoadServerGenericTemplates()
        {
            if (Templates.ContainsTag(GenericTemplateTag)) return;

            var templateNames = Reader.GetNames("generic", "tld");

            foreach (var templateName in templateNames)
            {
                var content = Reader.GetContent(templateName);

                Matcher.RegisterTemplate(content);
            }
        }
    }
}
