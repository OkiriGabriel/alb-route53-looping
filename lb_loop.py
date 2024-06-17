import boto3
import csv
import argparse
import logging
from botocore.exceptions import ClientError, BotoCoreError

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_load_balancers(file_path):
    """Read load balancer DNS names from a file."""
    with open(file_path, 'r') as file:
        return [line.strip().lower().rstrip('.') for line in file if line.strip()]

def get_dns_records(route53_client, zone_id):
    """Retrieve DNS records for the specified Route 53 zone."""
    paginator = route53_client.get_paginator('list_resource_record_sets')
    try:
        for page in paginator.paginate(HostedZoneId=zone_id):
            for record_set in page['ResourceRecordSets']:
                yield record_set
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            logging.error(f"Access denied for Zone ID {zone_id}. Check IAM permissions.")
            return []  # Return an empty list to handle gracefully
        else:
            raise

def resolve_arns_from_dns(elbv2_client, dns_names):
    """Resolve load balancer DNS names to their ARNs."""
    arns = {}
    for dns_name in dns_names:
        try:
            response = elbv2_client.describe_load_balancers()
            for lb in response['LoadBalancers']:
                if lb['DNSName'].lower() == dns_name.lower():
                    arns[dns_name] = lb['LoadBalancerArn']
                    break
        except (ClientError, BotoCoreError) as error:
            logging.error(f"API error while resolving ARN for {dns_name}: {error}")
            continue
    return arns

def match_dns_records(lb_arns, dns_records, output_file, region):
    """Match DNS records with load balancer ARNs and write results to CSV, including TLS policies."""
    with open(output_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        if file.tell() == 0:
            writer.writerow(['Region', 'Load Balancer ARN', 'Record Name', 'Record Type', 'TTL'])

        for dns_name, lb_arn in lb_arns.items():
            found_matches = []
            for record in dns_records:
                for resource in record.get('ResourceRecords', []):
                    if dns_name in resource.get('Value', '').lower():
                        found_matches.append([
                            region, lb_arn, record['Name'], record['Type'], record['TTL']
                        ])
                        logging.info(f"Match found in {region}: {lb_arn} -> {record['Name']}")
            if found_matches:
                for match in found_matches:
                    writer.writerow(match)
            else:
                logging.warning(f"No DNS record matches found for Load Balancer DNS: {dns_name} in {region}")

def main(args):
    # List of credentials for each account
    credentials_list = [
        {'access_key_id': '<key_id>', 'secret_access_key': '<secret_key>', 'session_token': '<Token>', 'zone_id': 'Z1IAXZ8AGKWGM8'},
        {'access_key_id': '<key_id>', 'secret_access_key': '<secret_key>', 'session_token': '<Token>', 'zone_id': 'Z1IAXZ8AGKWGM8'},
        {'access_key_id': '<key_id>', 'secret_access_key': '<secret_key>', 'session_token': '<Token>', 'zone_id': 'Z1IAXZ8AGKWGM8'},
        {'access_key_id': '<key_id>', 'secret_access_key': '<secret_key>', 'session_token': '<Token>', 'zone_id': 'Z1IAXZ8AGKWGM8'},
        {'access_key_id': '<key_id>', 'secret_access_key': '<secret_key>', 'session_token': '<Token>', 'zone_id': 'Z1IAXZ8AGKWGM8'},
        {'access_key_id': '<key_id>', 'secret_access_key': '<secret_key>', 'session_token': '<Token>', 'zone_id': 'Z1IAXZ8AGKWGM8'},
        {'access_key_id': '<key_id>', 'secret_access_key': '<secret_key>', 'session_token': '<Token>', 'zone_id': 'Z1IAXZ8AGKWGM8'},
    ]

    regions = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-west-1',
        'eu-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
        'sa-east-1', 'eu-north-1', 'ap-south-1', 'ap-east-1', 'me-south-1'
    ]

    for credentials in credentials_list:
        route53_client = boto3.client(
            'route53',
            aws_access_key_id=credentials['access_key_id'],
            aws_secret_access_key=credentials['secret_access_key'],
            aws_session_token=credentials['session_token']
        )

        dns_records = list(get_dns_records(route53_client, credentials['zone_id']))
        dns_names = read_load_balancers(args.load_balancer_file)
        for region in regions:
            elbv2_client = boto3.client(
                'elbv2',
                region_name=region,
                aws_access_key_id=credentials['access_key_id'],
                aws_secret_access_key=credentials['secret_access_key'],
                aws_session_token=credentials['session_token']
            )
            lb_arns = resolve_arns_from_dns(elbv2_client, dns_names)
            match_dns_records(lb_arns, dns_records, args.output_file, region)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Match DNS records in Route 53 to specified load balancer ARNs across multiple regions and report.')
    parser.add_argument('--load_balancer_file', required=True, help='File containing load balancer DNS names.')
    parser.add_argument('--output_file', required=True, help='CSV file to write output to.')
    args = parser.parse_args()

    main(args)
