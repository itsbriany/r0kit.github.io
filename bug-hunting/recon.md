# Recon

Recon is the very first thing that should happen when you sign up for a bug bounty program.
The more attack surface you have (that is in scope, of course), the more likely you will reach
uncharted territory where other bug hunters haven't been or spent as much time on which will
increase the likelyhood of you finding a bug. This will save you TONS of TIME!

Below is my methodology

## Enumerate Subdomains

Below is a list of online services for active and passive recon:

* [Pentest Tools](https://pentest-tools.com/)
* [Virus Total](https://virustotal.com/)
* [Shodan](https://www.shodan.io/)
* [crt.sh](https://crt.sh/) -> Search certificates
* [DNS Dumpster](https://dnsdumpster.com/)
* [Censys.io](https://censys.io)
* [dnsgoodies](http://dnsgoodies.com)

Below is a list of tools:

* [aquatone](https://github.com/michenriksen/aquatone) -> Take screenshots of sites that are worth attacking
* [sublist3r](https://github.com/aboul3la/Sublist3r) -> Enumerates subdomains with OSINT using various search engines
* [gobuster](https://github.com/OJ/gobuster) -> Dns brute forcing with user-supplied wordlists

## Enumerate Ports

Use [masscan](https://github.com/robertdavidgraham/masscan) to enumerate all ports on all in-scope subdomains.

## Enumerate Vhosts

## Enumerate S3 Buckets

S3 buckets may have public access controls on them and you might be able to view their contents.

## Google Dork

Use Google Dorks to find information leaks for the site in scope. If you're lucky, you might find a dev's private key!

## Searching GitHub and other public version control hosting

* [gitrob](https://github.com/michenriksen/gitrob) -> Find sensitive files in public GitHub repos.

## Searching Internet History

* [Wayback Machine](ttps://web.archive.org/)

## Spider in-scope sites that are interesting

## Map more attack surface from JavaScript source

The tool below will help you expose more endpoints.

* [relative-url-extractor](https://github.com/jobertabma/relative-url-extractor) -> Uses regexes to find urls in files.

## Burp Plugins

* Reflector -> Find reflected XSS faster as Burp spiders.

