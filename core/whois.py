#!/usr/bin/env python3

import warnings
import sys
import time
import concurrent.futures
import argparse
import validators
import dns.resolver
from ipwhois import IPWhois
import argcomplete


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)

def get_address(addr):
    """Checks if supplied address is name or IP, then calls ipwhois_addr(addr)"""
    # remove newlines and periods
    addr = addr.rstrip(".\n")
    results = []

    # covert DNS names to IP address
    if validators.domain(addr):
        myResolver = dns.resolver.Resolver()
        response = myResolver.query(addr, "A")
        for rdata in response:
            results.append(ipwhois_addr(rdata))

    # already an IP address
    else:
        results.append(ipwhois_addr(addr))

    return results



def ipwhois_addr(addr):
    """Performs IP whois lookup on IP address"""

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
        obj = IPWhois(addr)
        data = obj.lookup_rdap()

    asn_registry = data['asn_registry']
    cidr = data["network"]["cidr"]
    start_address = data["network"]["start_address"]
    end_address = data["network"]["end_address"]

    for result in data['objects']:
        try:
            if asn_registry in result.lower():
                continue
            if not "ripencc" in asn_registry:
                if data['objects'][result]['contact']['name']:
                    organization = data['objects'][result]['contact']['name']
                    break

            if data['network']['name']:
                organization = data['network']['name']
            else:
                organization = "Error retrieving organization name"
        except:
                organization = "Error retrieving organization name"

    results = {
        "cidr" : cidr,
        "start_address" : start_address,
        "end_address" : end_address,
        "organization" : organization
        }

    return results


def runner(targets):
    s = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
        futures = {executor.submit(get_address, target): target for target in targets}
        all_results = [  ]
        for future in concurrent.futures.as_completed(futures):
            result = futures[future]
            try:
                data = future.result()
                for item in data:
                    maxLength = 35
                    length_start = len(item["start_address"])
                    length_end = len(item["end_address"])
                    length = 3 + length_start + length_end
                    spacer = maxLength - length
                    return_string = item["start_address"] + " - " + item["end_address"] + ' ' * spacer + item["organization"]
                    # no duplicate results
                    if not return_string in all_results:
                        all_results.append(return_string)
            except Exception as exc:
                result = result.rstrip("\n.")
                print('%r generated an exception: %s' % (result, exc))

    all_results.sort()
    print()
    for result in all_results:
        print(result)

    elapsed = time.perf_counter() - s
    # print(f"\n{__file__} executed in {elapsed:0.2f} seconds.")
