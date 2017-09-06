#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# cflareupdate.py:    Update script for CrimeFlare database
# =============================================================================
# This script serves as a standalone script to update CrimeFlare data archives.
# Its purpose is to be run from crontab every so often.
#
# Compatible for both python 2.x and python 3.x.
#
# Pre-requisites:   requests, sqlite3, dnspython
#       python 2:   pip install sqlite3
#
#       python 3:   pip3 install sqlite3
#
# Pre-req notes:    It should be noted that older versions of the 'requests'
#                   module has a bug in handling download streams. You should
#                   make sure that you upgrade your packages caches:
#
#                   Debian/Ubuntu:  apt-get update
#                   FreeBSD:        pkg update
#
#                   Once you update your packages cache, use the aforementioned
#                   commands to install the required modules.
#
# Rhino Security Labs //hxm

# For use in making requests
import requests

# For handling command line arguments and parsing
import argparse

# Use sys.argv length to determine if arguments/options were specified
import sys

# Use os for file stats
import os

# Use zipfile for handling zip archives
import zipfile

try:
    import sqlite3
except:
    print("[-] You will need to install sqlite3 for python2/3")
    raise SystemExit

# Create global lists and dictionaries for use throughout
_found = []
_foundns = []
_nsdict = {}
_countrydict = {}

def downloadCFdb(cfdbpath, cfdbfile, updatehost):
    """Downloads CrimeFlare archive files into respective cfdbpath"""
    # Check to see if cfdbpath is writable
    if not os.path.isdir(cfdbpath):
        try:
            os.makedirs(cfdbpath)
        except(OSError):
                print('[-] Please use -p|--cfdbpath to specify writable directory path.')
                raise SystemExit

    _filename = '{}/{}'.format(cfdbpath, cfdbfile.split('/')[-1])

    # Download file to cfdbpath
    try:
        with open(_filename, 'wb') as f:
            print('[+] Downloading {} to {}'.format(cfdbfile, _filename))
            try:
                response = requests.get(cfdbfile, stream=True)
            except Exception:
                print('[-] Could not make connection to {}. Confirm you have correct host.'.format(updatehost))
                raise SystemExit
            if response.status_code != 200:
                print('[-] {} not found. Please enter correct host/path'.format(cfdbfile))
                raise SystemExit
            total_length = response.headers.get('content-length')

            if total_length is None:
                f.write(response.content)
            else:
                dl = 0
                total_length = int(total_length)
                for data in response.iter_content(chunk_size=int(total_length/100)):
                    dl += len(data)
                    f.write(data)
                    done = int(50 * dl / total_length)
                    sys.stdout.write('\r[{}{}]'.format('=' * done, ' ' * (50-done)) )
                    sys.stdout.flush()
        sys.stdout.write('\n')

    except(KeyboardInterrupt):
        sys.stdout.write('\r[-] CTRL+C Detected. Canceling download.')
        os.remove(_filename)
        sys.stdout.write('\n')
        raise SystemExit

def createCFdb(cfdbpath):
    """Initiates parsing and database creation"""
    print('[*] Creating SQLite3 Database into {}/cf.db'.format(cfdbpath))
    # Parse nsout archive into dict
    parsensout(cfdbpath)
    # Parse country archive into dict
    parsecountry(cfdbpath)
    # Parse ipout archive into list, and create database
    parseipout(cfdbpath)

def parsensout(cfdbpath):
    """Parse CrimeFlare's nsout.zip archive into a dictionary."""
    # Open nsout archive, parse out required data, store into a list
    try:
        znsout = zipfile.ZipFile('{}/nsout.zip'.format(cfdbpath))
        for finfo in znsout.infolist():
            ifile = znsout.open(finfo)
            for record in ifile.readlines():
                try:
                    NS1, NS2, DOMAIN = record.decode('utf-8').split()
                except Exception:
                    NSPLIT = record.decode('utf-8').split()
                    if len(NSPLIT) > 3:
                        DOMAIN = NSPLIT[-1]
                        NSPLIT.remove(DOMAIN)
                        NS1 = ' '.join(NSPLIT[:-2])
                        NS2 = ' '.join(NSPLIT[-2:])
                    pass
                _nsdict[DOMAIN] = '{} {}'.format(NS1, NS2)
    except(zipfile.BadZipfile):
        print("[-] Bad checksum on downloaded archive. Try to update again.")
        raise SystemExit

def parsecountry(cfdbpath):
    """Parse CrimeFlare's country.zip archive into a dictionary."""
    # Open country archive, parse out required data, store into a list
    try:
        zcountry = zipfile.ZipFile('{}/country.zip'.format(cfdbpath))
        for finfo in zcountry.infolist():
            ifile = zcountry.open(finfo)
            for record in ifile.readlines():
                try:
                    DOMAIN, IP, COUNTRY = record.decode('utf-8').split()
                except(ValueError):
                    COUNTRY = ' '.join(map(str, record.decode('utf-8').split()[2:]))
                _countrydict[DOMAIN] = '{}'.format(COUNTRY)
    except(zipfile.BadZipfile):
        print("[-] Bad checksum on downloaded archive. Try to update again.")
        raise SystemExit

def nsdictlookup(domain):
    """Lookup nameservers for respective domain keys."""
    if _nsdict.__contains__(domain):
        return _nsdict[domain]
    else:
        return 'N/A'


def countrydictlookup(domain):
    """Lookup nameservers for respective domain keys."""
    if _countrydict.__contains__(domain):
        return _countrydict[domain]
    else:
        return 'N/A'


def parseipout(cfdbpath):
    """Parses ipout archive and creates SQLite3 database for CrimeFlare data"""
    # Remove database if exists. Dropping tables/updating rows drags on time
    try:
        os.remove('{}/cf.db'.format(cfdbpath))
    except:
        pass

    # Connect to database
    conn = sqlite3.connect('{}/cf.db'.format(cfdbpath))
    c = conn.cursor()

    # Set PRAGMA variables for speed optimization purposes
    c.execute("PRAGMA foreign_keys=ON;")
    c.execute("PRAGMA synchronous=OFF;")
    c.execute("PRAGMA journal_mode=MEMORY;")
    c.execute("PRAGMA default_cache_size=10000;")
    c.execute("PRAGMA locking_mode=EXCLUSIVE;")

    # Structure our cfdb table to handle incoming data
    c.execute('''CREATE TABLE cfdb (domain TEXT, ip TEXT, created TEXT, nameservers TEXT, country TEXT)''')

    # Open ipout archive, parse out required data, store into a list
    _ipoutlst = list()
    try:
        zipout = zipfile.ZipFile('{}/ipout.zip'.format(cfdbpath))
        for finfo in zipout.infolist():
            ifile = zipout.open(finfo)
            for record in ifile.readlines():
                record = record.decode('utf-8').strip().split()
                _domain = record[1].rstrip()
                _ip = record[2]
                _created = record[0].strip(':')
                _ipoutlst.append((_domain, _ip, _created, nsdictlookup(_domain), countrydictlookup(_domain)))
    except(zipfile.BadZipfile):
        print("[-] Bad checksum on downloaded archive. Try to update again.")
        raise SystemExit
    # Add data into database.
    c.executemany("INSERT INTO cfdb VALUES (?,?,?,?,?)", _ipoutlst)
    conn.commit()
    conn.close()

def updateCFdb(cfdbpath, updatehost):
    """Updates CrimeFlare archives"""
    # Check if files exist, download them otherwise
    if not os.access('{}/ipout.zip'.format(cfdbpath), os.R_OK):
        print("[-] ipout archive missing. Downloading to {}/ipout.zip".format(cfdbpath))
        downloadCFdb(cfdbpath, '{}/ipout.zip'.format(updatehost), updatehost)

    if not os.access('{}/nsout.zip'.format(cfdbpath), os.R_OK):
        print("[-] nsout archive missing. Downloading to {}/nsout.zip".format(cfdbpath))
        downloadCFdb(cfdbpath, '{}/nsout.zip'.format(updatehost), updatehost)

    if not os.access('{}/country.zip'.format(cfdbpath), os.R_OK):
        print("[-] country archive missing. Downloading to {}/country.zip".format(cfdbpath))
        downloadCFdb(cfdbpath, '{}/country.zip'.format(updatehost), updatehost)

    # Grab filesizes of current archives
    fipout = os.stat('{}/ipout.zip'.format(cfdbpath)).st_size
    fnsout = os.stat('{}/nsout.zip'.format(cfdbpath)).st_size
    fcountry = os.stat('{}/country.zip'.format(cfdbpath)).st_size

    # HEAD requests to updatehost, compare filesizes to determine if we need to
    # freshen archives.
    try:
        ripout = requests.head('{}/ipout.zip'.format(updatehost), headers={'Accept-Encoding': 'identity'})
        rnsout = requests.head('{}/nsout.zip'.format(updatehost), headers={'Accept-Encoding': 'identity'})
        rcountry = requests.head('{}/country.zip'.format(updatehost), headers={'Accept-Encoding': 'identity'})
    except Exception:
        print('[-] Could not make connection to {}. Confirm you have correct host.'.format(updatehost))
        raise SystemExit

    if ripout.status_code == 200 and rnsout.status_code == 200 and rcountry.status_code == 200:
        if int(ripout.headers['content-length']) != fipout:
            print('[+] Updating ipout.zip')
            downloadCFdb(cfdbpath, '{}/ipout.zip'.format(updatehost), updatehost)
        if int(rnsout.headers['content-length']) != fnsout:
            print('[+] Updating nsout.zip')
            downloadCFdb(cfdbpath, '{}/nsout.zip'.format(updatehost), updatehost)
        if int(rcountry.headers['content-length']) != fcountry:
            print('[+] Updating country.zip')
            downloadCFdb(cfdbpath, '{}/country.zip'.format(updatehost), updatehost)
        else:
            print('[+] The ipout/nsout archives are up to date')
            if not os.access('{}/cf.db'.format(cfdbpath), os.R_OK):
                createCFdb(cfdbpath)
    else:
        print('[-] Archives missing on host. Check URL.')


def main():
    # Configure argument parser
    parser = argparse.ArgumentParser(
        prog='cflareupdate.py',
        description='Updater script for CrimeFlare archives',
        epilog='For educational purposes only. @hxmonsegur//RSL',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-d', '--updatehost', help='Host serving CrimeFlare files', default='http://crimeflare.net:82/domains/')
    parser.add_argument('-p', '--cfdbpath', help='Path to cfdb directory', default='/tmp/cfdb')
    parser.add_argument('-u', '--update', help='Designate whether we are updating', action='store_true')

    # Parse arguments
    try:
        args = parser.parse_args()
    except:
        parser.print_help()
        raise SystemExit

    if len(sys.argv) <= 1:
        parser.print_help()
        raise SystemExit

    if args.update:
        print("[+] Starting update procedure")
        updateCFdb(args.cfdbpath, args.updatehost)

if __name__ == "__main__":
    main()
