﻿using System;
using System.Text;

namespace Whois
{
    /// <summary>
    ///  Represents a request to query WHOIS information
    /// </summary>
    public class WhoisRequest
    {
        /// <summary>
        /// Creates a request for the given query with the default options
        /// </summary>
        /// <param name="query"></param>
        public WhoisRequest(string query)
        {
            if (string.IsNullOrWhiteSpace(query))
                throw new ArgumentNullException(nameof(query));

            if (query.StartsWith("."))
                query = query.TrimStart('.');

            if (HostName.TryParse(query, out var hostname) == false)
                throw new WhoisException($"WHOIS Query Format Error: {Query}");

            Query = query;
            HostName = hostname;
            Encoding = WhoisOptions.Defaults.Encoding;
            TimeoutSeconds = WhoisOptions.Defaults.TimeoutSeconds;
            FollowReferrer = true;
        }

        /// <summary>
        /// The WHOIS query, typically the domain name
        /// </summary>
        public string Query { get; internal set; }

        /// <summary>
        /// The encoding to use whilst reading data from the WHOIS server
        /// </summary>
        public Encoding Encoding { get; set; }

        /// <summary>
        /// The network timeout to use whilst reading data from the WHOIS server
        /// </summary>
        public int TimeoutSeconds { get; set; }

        /// <summary>
        /// Is true, then referral links within WHOIS responses will be followed.
        /// </summary>
        public bool FollowReferrer { get; set; }

        /// <summary>
        /// If set, the given WHOIS server will be queried.  If blank, the WHOIS
        /// server for the domain TLD will be attempted to be found automatically.
        /// </summary>
        public string WhoisServer { get; set; }


        public HostName HostName { get; private set; }
    }
}
