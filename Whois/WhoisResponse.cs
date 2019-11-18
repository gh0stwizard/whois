using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;

namespace Whois
{
    /// <summary>
    /// Represents WHOIS information for a domain.
    /// </summary>
    public class WhoisResponse
    {
        public Type ResponseType { get; internal set; } = typeof(WhoisResponse);


        /// <summary>
        /// Contains the raw response returned from the WHOIS server
        /// </summary>
        public string Content { get; set; }

        /// <summary>
        /// Returns the length of the content from the WHOIS server
        /// </summary>
        public int ContentLength => string.IsNullOrEmpty(Content) ? 0 : Content.Length;

        /// <summary>
        /// Returns the status of this WHOIS lookup
        /// </summary>
        public WhoisStatus Status { get; set; } = WhoisStatus.Unknown;

        /// <summary>
        /// The number of fields parsed from the raw WHOIS response
        /// </summary>
        public int FieldsParsed { get; set; }

        /// <summary>
        /// The number of parsing errors that occured whilst parsing this WHOIS response
        /// </summary>
        public int ParsingErrors { get; set; }

        /// <summary>
        /// The template that was used to parse this WHOIS response
        /// </summary>
        public string TemplateName { get; set; }

        /// <summary>
        /// The referring WHOIS server, if any
        /// </summary>
        public WhoisResponse Referrer { get; set; }

        /// <summary>
        /// Gets or sets the registrar
        /// </summary>
        public Registrar Registrar { get; set; }

        /// <summary>
        /// Returns the URL of the WHOIS server
        /// </summary>
        public HostName WhoisServer => Registrar?.WhoisServer;


        /// <summary>
        /// Returns a new <see cref="WhoisResponse"/> with the specified WHOIS host name 
        /// </summary>
        internal static WhoisResponse WithServerUrl(string hostName)
        {
            return new WhoisResponse
            {
                Status = WhoisStatus.Found,
                Registrar = new Registrar
                {
                    WhoisServer = new HostName(hostName)
                }
            };
        }

        /// <summary>
        /// Sets the WHOIS referrer on this instance
        /// </summary>
        internal WhoisResponse Chain(WhoisResponse response)
        {
            response.Referrer = this;

            return response;
        }

        /// <summary>
        /// Determines if the given WHOIS server URL has been visited in this lookup chain
        /// </summary>
        internal bool SeenServer(HostName whoisServer)
        {
            return SeenServer(whoisServer, 0);
        }

        private bool SeenServer(HostName whoisServer, int depth)
        {
            // Referral limit
            if (depth > 255) return true;

            // Ignore top level request
            if (depth == 0) return Referrer?.SeenServer(whoisServer, 1) ?? false;


            if (WhoisServer.IsEqualTo(whoisServer))
            {
                return true;
            }

            return Referrer != null && Referrer.SeenServer(whoisServer, depth + 1);
        }
    }
}