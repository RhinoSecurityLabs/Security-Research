#!/usr/bin/env python3

# Spencer Gietzen of Rhino Security Labs
# GitHub: https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/aws-pentest-tools/awshoney_check

import argparse
import boto3
import botocore
import re

def main(args):
    if args.profile == None:
        session = boto3.session.Session()
        print('No AWS CLI profile passed in, choose one below or rerun the script using the -p/--profile argument:')
        profiles = session.available_profiles
        for i in range(0, len(profiles)):
            print('[{}] {}'.format(i, profiles[i]))
        profile_number = int(input('Choose a profile (Ctrl+C to exit): ').strip())
        session = boto3.session.Session(profile_name=profiles[profile_number])
    else:
        try:
            session = boto3.session.Session(profile_name=args.profile)
        except botocore.exceptions.ProfileNotFound as error:
            print('Did not find the specified AWS CLI profile: {}\n'.format(args.profile))

            session = boto3.session.Session()
            print('Profiles that are available: {}\n'.format(session.available_profiles))
            print('Quitting...\n')
            sys.exit(1)

    client = session.client(
        'appstream',
        region_name='us-east-1'
    )

    print('\nMaking test API request...\n')

    try:
        client.tag_resource(
            ResourceArn='asdfghjksdafsdfsfasdfasflmnop',
            Tags={
                'asd': 'asd'
            }
        )
        print('  API call was successful somehow, this shouldn\'t be possible!\n')
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            message = error.response['Error']['Message']

            if 'arn:aws:iam::534261010715:user/canarytokens.com' in message:
                print('  WARNING: Keys are confirmed honeytoken keys from Canarytokens.org! Do not use them!\n')
            elif 'arn:aws:iam::' in message and '/SpaceCrab/' in message:
                print('  WARNING: Keys are confirmed honeytoken keys from SpaceCrab! Do not use them!\n')
            elif 'arn:aws:iam::534261010715:' in message or 'arn:aws:sts::534261010715:' in message:
                print('  WARNING: Keys belong to an AWS account owned by Canarytokens.org! Do not use them!\n')
            else:
                print('  Keys appear to be real (not honeytoken keys)!\n')

            match = re.search('arn:.* is not', message)
            if match:
                print('  Full ARN for the keys:\n    {}\n'.format(match.group()[:-7]))
        else:
            print('  Unhandled error received: {}\n'.format(error.response['Error']['Code']))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script takes a set of AWS API keys and tries to determine whether they are honeytoken keys. AWS honeytokens are strategically placed in various locations, such as a private Git repo, on the file system of a certain server, and other similar places. Their main purpose is to detect when an attacker has breached their environment. An attacker would likely use AWS keys that they find, but aws honeytokens have no permissions and immediately alert the account owner when they are used. This is a "defense in depth" protection to detect malicious users with access to certain areas of an environment. This script abuses the AWS API by trying to run a command against an AWS service that is not supported by CloudTrail. Because the targeted service is not supported by CloudTrail, there will never be an alert that the keys were compromised and used. This makes it possible to detect whether or not a set of AWS keys are boobytrapped without triggering the alerts behind them.', epilog='Currently this script supports detection for two separate canary/honeytoken services provided online. The two services include https://canarytokens.org/ by Thinkst Canary and SpaceCrab by Atlassian. All tokens generated from https://canarytokens.org/ are vulnerable to this detection and only default configurations of SpaceCrab are affected.')

    parser.add_argument('-p', '--profile', required=False, help='The AWS CLI profile to use. You will be prompted if this argument is omitted')

    args = parser.parse_args()

    main(args)