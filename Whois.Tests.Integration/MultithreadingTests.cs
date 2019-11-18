﻿using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using Whois.Models;

namespace Whois
{
    [TestFixture]
    public class MultithreadingTests
    {
        private WhoisLookup lookup;

        [SetUp]
        public void SetUp()
        {
            lookup = new WhoisLookup();
        }

        [Test]
        public void TestDownloadSampleDomainsSingleThreaded()
        {
            var domains = new SampleReader().ReadSampleDomains();

            foreach (var domain in domains)
            {
                Console.WriteLine($"Looking Up: {domain.DomainName}");

                DomainResponse response = null;

                try
                {
                    var result = lookup.Lookup(domain.DomainName);

                    if (result.ResponseType != typeof(DomainResponse))
                        throw new Exception(string.Format("Invalid response type: {0}", result.ResponseType.Name));

                    response = (DomainResponse)result;

                    Console.WriteLine($"Looked Up: {domain.DomainName}, Status: {response.Status}, Size: {response.Content.Length}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"FAIL: {response?.DomainName}: {e.Message}");
                }
                Thread.Sleep(1000);
            }
        }

        [Test]
        public async Task TestDownloadSamplesDomainsMultipleThreaded()
        {
            var domains = new SampleReader().ReadSampleDomains();

            var queue = new ConcurrentQueue<SampleDomain>(domains);
            var responses = new ConcurrentBag<DomainResponse>();

            var tasks = Enumerable.Range(1, 25).Select(async i => 
            {
                while (queue.IsEmpty == false)
                {
                    if (!queue.TryDequeue(out var domain)) continue;

                    Console.WriteLine($"Looking Up: {domain.DomainName}");

                    try
                    {
                        var response = await lookup.LookupAsync(domain.DomainName);

                        if (response != null && response.ResponseType == typeof(DomainResponse))
                        {
                            responses.Add((DomainResponse)response);
                        }
                        else
                        {
                            Console.WriteLine($"NULL: {domain.DomainName}");
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"FAIL: {domain.DomainName}: {e.Message}");
                    }
                }
            });

            await Task.WhenAll(tasks);

            foreach (var response in responses)
            {
                Console.WriteLine($"Looked Up: {response.DomainName}, Status: {response.Status}, Size: {response.ContentLength}");
            }
        }
    }
}
