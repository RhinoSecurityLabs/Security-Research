# AWS Tools

## buckethead.py

### Requirements
```
python3
python3-pip
pip3
# Sublist3r's Requirements
argparse
dnspython
requests
```

### Description
buckethead.py searches across every AWS region for a variety of bucket names based on a domain name, subdomains, affixes given and more. Currently the tool will only present to you whether or not the bucket exists or if they're listable. If the bucket is listable, then further interrogation of the resource can be done. It does not attempt download or upload permissions currently but could be added as a module in the future. You will need the `awscli` to run this tool as this is a python wrapper around this tool.  

To get your access key id and secret access key, following the url here:  
* http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html

This tool is an iteration on the inital tool that was used for tertiary S3 analysis of the Alexa Top 10,000 found here:  
* https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/

This project uses Sublist3r (https://github.com/aboul3la/Sublist3r) to enumerate interesting subdomains. Be careful running this tool several times in a row, as several providers will pick up on multiple DNS lookups.  

A special thanks to flaws.cloud for being a great resource to learn about AWS security.

### Installation
#### apt-get users
Simply run the ./setup.sh script to get started.

#### Others...
Ensure you have python3 installed, along with pip3. Then clone the Sublist3r repository into the same directory as this script and install the requirements via `pip3 install -r Sublist3r/requirements.txt`. Afterwards edit the Sublist3r/sublist3r.py file's import section and change the line that reads `from subbrute import subbrute` to `from Sublist3r.subbrute import subbrute`.

### Example Usage

Use sublist3r to get a list of subdomains using subbrute and search for buckets.  

`./buckethead.py -d flaws.cloud -t 10 --sublist3r --subbrute`

![alt text](http://i.imgur.com/Hi8J6vi.png)

Use the brute force list to add affixes. Note: This will be a lot, a lot of buckets.  

`./buckethead.py -d flaws.cloud -b -t 30`

Attach a list of various affixes to the domain and for each bucket found, grep for keywords.  

`./buckethead.py -d flaws.cloud -f affix_list.txt -g keywords.txt`

