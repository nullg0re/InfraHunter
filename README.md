# InfraHunter

A tool to quickly identify cloud infrastructure against a given target.  The key here is netblock ownership.

This tool will run amass passively against a given target for 10 minutes.

It will then run amass actively against a given target for 10 minutes.

InfraHunter.py will then iterate through all of the collected possible IP address and attempt to identify it's DNS A record.

With the list of valid IP addresses, InfraHunter will then perform a whois lookup against the IP address and print out the netblock owner for the given IPs.

We are looking for Google, Amazon, Microsoft, Digital Ocean, and other cloud providers.

This lets us know through passive OSINT what cloud providers the company leverages to perform daily operations and expands our attack surface.

This tool can be used against a single domain or a list of domains with the amass switch `-df` or `--domainFile`


## Usage
```bash
$ python3 InfraHunter.py --help   

usage: InfraHunter.py [-h] [-d DOMAIN] [-df DOMAINFILE]

Amass Subdomain Collecter and Scope Resolver

options:
  -h, --help                               show this help message and exit

  -d DOMAIN, --domain DOMAIN               Domain. I.E. example.com

  -df DOMAINFILE, --domainFile DOMAINFILE  File Containing List of Domains

```
