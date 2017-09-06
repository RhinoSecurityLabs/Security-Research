Rhino Security Labs, Inc.
www.RhinoSecurityLabs.com    |    info@rhinosecuritylabs.com
(888) 944-8679    |    1200 East Pike Street, Suite 510, Seattle, WA 98115 
     
/*******************************************************************************************************/

CloudFire
=========

This project focuses on discovering potential IP's leaking from behind cloud-proxied services, e.g. CloudFlare. Although there are many ways to tackle this task, we are focusing right now on CrimeFlare database lookups, search engine scraping and other enumeration techniques.

Eventually, as the project grows, it will become more modular and much more sophisticated in usage. 


Installation
============

Install required python modules:
pip install -r requirements.txt

Run installer script which simply git clones Sublist3r
./install.sh 

Ideas for future discovery methods:

- WordPress pingbacks
- SSRF vulnerabilities
- OOB vulnerabilities (XXE, SQL injection, etc)
- Brute forcing DNS records - important.
- Other asset discovery methods

