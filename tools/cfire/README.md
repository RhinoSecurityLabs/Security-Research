/*
*
* 8888888b.  888    888 8888888 888b    888  .d88888b. 
* 888   Y88b 888    888   888   8888b   888 d88P" "Y88b
* 888    888 888    888   888   88888b  888 888     888
* 888   d88P 8888888888   888   888Y88b 888 888     888
* 8888888P"  888    888   888   888 Y88b888 888     888
* 888 T88b   888    888   888   888  Y88888 888     888
* 888  T88b  888    888   888   888   Y8888 Y88b. .d88P
* 888   T88b 888    888 8888888 888    Y888  "Y88888P" 
* 
*  .d8888b.  8888888888 .d8888b.  888     888 8888888b.  8888888 88888888888 Y88b   d88P
* d88P  Y88b 888       d88P  Y88b 888     888 888   Y88b   888       888      Y88b d88P
* Y88b.      888       888    888 888     888 888    888   888       888       Y88o88P
*  "Y888b.   8888888   888        888     888 888   d88P   888       888        Y888P
*     "Y88b. 888       888        888     888 8888888P"    888       888         888
*       "888 888       888    888 888     888 888 T88b     888       888         888
* Y88b  d88P 888       Y88b  d88P Y88b. .d88P 888  T88b    888       888         888
*  "Y8888P"  8888888888 "Y8888P"   "Y88888P"  888   T88b 8888888     888         888
*
* www.RhinoSecurityLabs.com    |    info@rhinosecuritylabs.com
* (888) 944-8679    |    1200 East Pike Street, Suite 510, Seattle, WA 98115 
*     
***********************************************************************************************************/

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

