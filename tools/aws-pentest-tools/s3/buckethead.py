#!/usr/bin/env python3
# Author: Dwight Hohnstein, Rhino Security Labs (dwight.hohnstein@rhinosecuritylabs.com)
from subprocess import check_output, CalledProcessError
from os import devnull
import logging
import sys
import traceback
from optparse import OptionParser
from queue import Queue
from threading import Thread

from settings import S3_REGIONS


logging.basicConfig(filename='bucket-tally.log', level=logging.INFO)

bucket_q = Queue()
bucket_q_size = 0

# Bucketlist to sort buckets based on permissions.
bucketlist = {
    "exists": [],
    "listable": [],
}


G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white


def check_region_choice(regions):
    """
    Check that the region passed to the script is valid. If all,
    return all regions.

    Args:
        regions (str): Comma separated string of regions.

    Returns:
        list: List of AWS regions.
    """
    regions = [x.strip() for x in regions.split(",")]
    if "all" in regions:
        return S3_REGIONS
    elif not all(x in S3_REGIONS for x in regions):
        # Not all regions passed to program are valid, raise error.
        print("Invalid option passed for -r (--regions). Regions must be one or more of the following:")
        print("all, {}".format(", ".join(S3_REGIONS)))
        exit(1)
    else:
        # Every region passed is valid!
        return regions

def create_bucket_list(domain, affixes=[]):
    """
    Create a set of buckets based on a domain name and a list of affixes.
    Note: This will be very large.

    Args:
        domain   (str): Domain to add affixes to, such as google.com
        regions (list): List of AWS regions to query against.
        affixes (list): List of affixes to prefix and suffix to domain.

    Returns:
        set: Set of domain permutations.

    Example:
        > buckets = create_bucket_list("google.com", ["01"])
        > buckets
        ["google.com", "google", "01.google.com", "01.google", "01-google",
        "01google", "01google.com", "google-01", "google01"]
    """
    perms = set()
    # add domain
    perms.add(domain)
    rootword = ".".join(domain.split(".")[:-1])
    # add rootword
    perms.add(rootword)
    for affix in affixes:
        # affix.domain
        perms.add("{}.{}".format(affix, domain))
        # affix.rootword
        perms.add("{}.{}".format(affix, rootword))
        # affix-rootword
        perms.add("{}-{}".format(affix, rootword))
        # affixdomain
        perms.add("{}{}".format(affix, domain))
        # affixrootword
        perms.add("{}{}".format(affix, rootword))
        # rootword-affix
        perms.add("{}-{}".format(rootword, affix))
        # rootwordaffix
        perms.add("{}{}".format(rootword, affix))
    return perms

def bucket_worker():
    """
    Wrapper to fetch items from queue and query s3
    """

    while not bucket_q.empty():
        region, bucket = bucket_q.get(timeout=5)
        currcount = bucket_q_size - bucket_q.qsize()
        percentile = round((float(currcount)/float(bucket_q_size))*100, 2)
        print("Buckets searched: {}% ({}/{})".format(percentile, currcount, bucket_q_size), end="\r")
        try:
            ls_s3(region, bucket)
        except CalledProcessError:
            pass
        bucket_q.task_done()

def ls_s3(region, domain):
    """
    Takes a region and domain to query awscli and determine if the
    bucket exists or is is listable. Pushes results to bucketlist
    dictionary.

    Args:
        region (str): One of the AWS regions specified in settings.py
        domain (str): Domain to target with s3://domain/

    Returns:
        None: No return value as it populates bucketlist
    """
    fails = ["(InvalidBucketName)", "(NoSuchBucket)", "(PermanentRedirect)"]
    exists = ["(AllAccessDisabled)", "(AccessDenied)", "(InvalidAccessKeyId)"]

    cmd = "aws s3 ls s3://{}/ --region {}".format(domain, region)

    # Redirect stdout to null
    with open(devnull, 'w') as FNULL:
        output = str(check_output(cmd.split(), stderr=FNULL))

    logging.debug("Running command: {}".format(cmd))
    logging.debug("Output was:\n{}".format(output))

    if not any(x in output for x in fails):
        info = (domain, region)
        if any(x in output for x in exists):
            bucketlist['exists'].append(info)
            print("[E] {}{} {}on {}{} {}exists.\n".format(Y, domain, W, Y, region, W))
            logging.info('[EXISTS] ' + cmd + "\n" + output + "\n" + "-"*10 + "\n")
        else:
            bucketlist['exists'].append(info)
            bucketlist['listable'].append(info)
            print("[L] {}{} {}on {}{} {}is listable.\n".format(G, domain, W, G, region, W))
            logging.info("[LISTABLE] " + cmd + "\n" + output + "\n" + "-"*10 + "\n")

def main():
    """
    Main function block that parses command line arguments.
    """
    usage = "usage: %prog -d domain.com [-f keywords.txt -r region1,region2 -b" + \
     "-t 30 -g keyword_file.txt -s [--subbrute]]"
    parser = OptionParser(usage)

    parser.add_option("-f", "--file", dest="filename", help="Read affixes from FILENAME.")
    parser.add_option("-r", "--regions", dest="regions", default="all", help="Comma separated list " +
    "of regions to query for bucket names. Default is all. Must be one or more of:" +
    "{}".format(", ".join(S3_REGIONS)))
    parser.add_option("-b", "--brute", dest="brute", action="store_true",
                      help="Use default brute force list in Buckets.txt")
    parser.add_option("-t", "--threads", dest="threads", type="int", default=6,
                      help="Max number of threads, default is 6.")
    parser.add_option("-g", "--grep", dest="grep",
                      help="Will recursively list files from buckets (when listable) and grep " +
                      "for keywords FILENAME. Ex: -g sensitive_keywords.txt")
    parser.add_option("--sublist3r", dest="sublister", action="store_true", default=False,
                      help="Retrieve list of subdomains and use this to query against S3.")
    parser.add_option("--subbrute", dest="subbrute", action="store_true", default=False,
                      help="Enable sublist3r's subbrute module when querying for subdomains.")
    parser.add_option("-d", "--domain", dest="domain", help="Base domain to be queried against.")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Enable debug messages in logs.")


    (options, args) = parser.parse_args()

    # Begin option parsing brick

    # Set logging
    if options.verbose:
        logging.getLogger().setLevel(level=logging.DEBUG)


    # Check regions passed are valid
    regions = check_region_choice(options.regions)

    # List of affixes to append to domain.com and domain in the form of
    # affix.domain.com and affix-domain
    affixes = []

    # Subdomain var to keep track of sublist3r results.
    subdomains = []

    if not options.domain:
        print("No argument -d (--domain) given. Please give a domain name, such as -d google.com")
        exit(1)

    # Read default keyword list if bruteforcing
    if options.brute:
        with open("Buckets.txt", "r") as f:
            affixes += [x.strip() for x in f.readlines()]

    # Read filename of user-provided keywords
    if options.filename:
        with open(options.filename, "r") as f:
            affixes += [x.strip() for x in f.readlines()]

    if options.sublister:
        from Sublist3r import sublist3r
        subdomains = sublist3r.main(options.domain, 30, None, None, False, verbose=True, enable_bruteforce=options.subbrute, engines=None)

    buckets = create_bucket_list(options.domain, affixes=affixes)

    for subdomain in subdomains:
        subucks = create_bucket_list(subdomain, affixes=affixes)
        buckets = buckets.union(subucks)

    for region in regions:
        for bucket in buckets:
            bucket_q.put((region, bucket))

    print("Generated {} bucket permutations. Beginning search across {} regions.".format(len(buckets), len(regions)))
    print()

    global bucket_q_size
    bucket_q_size = bucket_q.qsize()

    for i in range(options.threads):
        t = Thread(target=bucket_worker, args=())
        t.daemon = True
        t.start()

    bucket_q.join()

    print()
    print("[+] Results:")
    print("\t{}Number of Buckets that Exist: {}{}".format(Y,len(bucketlist['exists']), W))
    print("\t{}Number of Buckets that are Listable: {}{}".format(G,len(bucketlist['listable']), W))

    if options.grep and bucketlist['listable']:
        print("[.] Grepping for keywords in listable buckets from {}".format(options.grep))
        with open(options.grep, 'r') as f:
            keywords = [x.strip().lower() for x in f.readlines() if x.strip()]
        for domain, region in bucketlist['listable']:
            cmd = "aws s3 ls s3://{}/ --region {} --recursive".format(domain, region)
            cmd = cmd.split(" ")
            with open(devnull, 'w') as FNULL:
                output = check_output(cmd, stderr=FNULL)
            output = output.lower()
            if any(x in output for x in keywords):
                print("[!] Found sensitive file on bucket {} in region {}".format(domain, region))

if __name__ == "__main__":
    main()
