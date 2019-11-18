using System;
using System.Collections.Generic;
using System.Text;

namespace Whois
{
    public class DomainResponse : WhoisResponse
    {
        public DomainResponse()
        {
            ResponseType = typeof(DomainResponse);
        }


        /// <summary>
        /// Gets the domain name
        /// </summary>
        public HostName DomainName { get; set; }

        /// <summary>
        /// Gets the registry Domain Id
        /// </summary>
        public string RegistryDomainId { get; set; }

        /// <summary>
        /// Gets the domain name statuses
        /// </summary>
        public IList<string> DomainStatus { get; } = new List<string>();

        /// <summary>
        /// Gets or sets the date the domain was registered.
        /// </summary>
        public DateTime? Registered { get; set; }

        /// <summary>
        /// Gets or sets the date the domain was last updated
        /// </summary>
        public DateTime? Updated { get; set; }

        /// <summary>
        /// Gets or sets the expiration date of the domain
        /// </summary>
        public DateTime? Expiration { get; set; }

        /// <summary>
        /// Gets or sets the registrant.
        /// </summary>
        public Contact Registrant { get; set; }

        /// <summary>
        /// Gets or sets the technical contact.
        /// </summary>
        public Contact TechnicalContact { get; set; }

        /// <summary>
        /// Gets or sets the admin contact.
        /// </summary>
        public Contact AdminContact { get; set; }

        /// <summary>
        /// Gets or sets the billing contact
        /// </summary>
        public Contact BillingContact { get; set; }

        /// <summary>
        /// Gets or sets the zone contact
        /// </summary>
        public Contact ZoneContact { get; set; }

        /// <summary>
        /// Gets the domain name servers
        /// </summary>
        public IList<string> NameServers { get; } = new List<string>();

        /// <summary>
        /// Contains any remarks about the domain registration
        /// </summary>
        public string Remarks { get; set; }

        /// <summary>
        /// Contains the DNS Sec status
        /// </summary>
        public string DnsSecStatus { get; set; }

        /// <summary>
        /// Contains any trademark information about this registration
        /// </summary>
        public Trademark Trademark { get; set; }
    }
}
