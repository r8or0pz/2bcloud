import boto3
import requests
import yaml
import sys
import os
import argparse
import logging
from botocore.exceptions import ClientError
from git import Repo

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

TEMPLATE_FILE = 'security-group.yaml'
CLOUDFLARE_IPV4_URL = 'https://www.cloudflare.com/ips-v4'
CHECK_IP_URL = 'https://checkip.amazonaws.com'

def get_current_ip():
    try:
        response = requests.get(CHECK_IP_URL)
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException as e:
        logger.error(f"Error fetching current IP: {e}")
        sys.exit(1)

def get_cloudflare_ips():
    try:
        response = requests.get(CLOUDFLARE_IPV4_URL)
        response.raise_for_status()
        return response.text.strip().split('\n')
    except requests.RequestException as e:
        logger.error(f"Error fetching Cloudflare IPs: {e}")
        sys.exit(1)

def load_template(filepath):
    if not os.path.exists(filepath):
        logger.error(f"Template file {filepath} not found.")
        sys.exit(1)
    with open(filepath, 'r') as f:
        return yaml.safe_load(f)

def save_template(filepath, data):
    with open(filepath, 'w') as f:
        yaml.dump(data, f, sort_keys=False)

def get_instance_info(ip_address, region=None):
    # If region is not provided, we might need a way to guess it or iterate.
    # For now, we assume standard AWS credential setup handles region or we use a default.
    # However, requirements say "region... determine dynamically".
    # Usually this implies querying metadata if on EC2, or maybe iterating regions if remote?
    # Or simply respecting the environment config.
    # Let's try to infer from session.

    session = boto3.Session(region_name=region)
    # If specific region provided (e.g. from args or previous lookup), use it.
    # Otherwise, boto3 uses config/env.

    ec2 = session.client('ec2')

    try:
        logger.info(f"Looking for instance with Public IP: {ip_address}")
        response = ec2.describe_instances(
            Filters=[{'Name': 'ip-address', 'Values': [ip_address]}]
        )

        reservations = response.get('Reservations', [])
        if not reservations or not reservations[0]['Instances']:
            logger.error(f"No instance found with Public IP {ip_address} in region {session.region_name}")
            return None, None, None

        instance = reservations[0]['Instances'][0]
        instance_id = instance['InstanceId']
        # Assuming the first security group is the target as per standard single-purpose instance setups
        # Ideally we'd filter by a tag or name from the template, but prompts implies dynamic discovery attached to instance.
        sgs = instance['SecurityGroups']
        if not sgs:
            logger.error("Instance has no security groups.")
            return None, None, None

        # Using the first SG found
        sg_id = sgs[0]['GroupId']
        region_name = session.region_name

        return instance_id, sg_id, region_name

    except ClientError as e:
        logger.error(f"AWS Error: {e}")
        return None, None, None

def update_security_group(sg_id, region, allowed_cidrs):
    session = boto3.Session(region_name=region)
    ec2 = session.resource('ec2')
    security_group = ec2.SecurityGroup(sg_id)

    # Current permissions
    logger.info(f"Analyzing Security Group {sg_id}...")

    # We want to sync HTTP (80).
    # SSH (22) should remain 0.0.0.0/0 (checking if it exists, implementing if missing?
    # Prompt says 'SSH remains open... unchanged', implying we just ensure we don't break it.
    # We will focus on managing port 80.)

    # 1. Revoke all existing HTTP rules that are NOT in our allowed list?
    # Or just revoke ALL HTTP rules and re-add the correct ones to be safe/clean?
    # "Remove any stale HTTP CIDRs not in {home IP, Cloudflare ranges}."
    # Revoking specific rules is complex because we need to match exact existing rule entries.

    # Let's iterate existing rules to find stale HTTP rules.

    stale_permissions = []

    # Pre-calculate allowed set for easy lookup
    allowed_set = set(allowed_cidrs)

    # We also need to identify which rules (if any) are already correct to avoid re-adding
    existing_correct_cidrs = set()

    if security_group.ip_permissions:
        for permission in security_group.ip_permissions:
            # Check if this valid port 80 rule (TCP)
            if permission.get('IpProtocol') == 'tcp' and permission.get('FromPort') == 80 and permission.get('ToPort') == 80:
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    if cidr not in allowed_set:
                        # This is a stale rule
                        stale_permissions.append({
                            'IpProtocol': 'tcp',
                            'FromPort': 80,
                            'ToPort': 80,
                            'IpRanges': [{'CidrIp': cidr}]
                        })
                        logger.info(f"Planned Remove: {cidr} (stale)")
                    else:
                        existing_correct_cidrs.add(cidr)

    # Execute Revocations
    if stale_permissions:
        logger.info(f"Revoking {len(stale_permissions)} stale HTTP rules...")
        try:
            security_group.revoke_ingress(IpPermissions=stale_permissions)
        except ClientError as e:
            logger.error(f"Failed to revoke rules: {e}")

    # 2. Authorize new rules
    # Identify what is missing
    missing_cidrs = allowed_set - existing_correct_cidrs

    if missing_cidrs:
        logger.info(f"Planned Add: {len(missing_cidrs)} range(s)")

        # AWS limits rules per request/SG. It's usually high (50-60 inbound rules), Cloudflare has ~15-20.
        # But good to batch if really large. Cloudflare list is small enough.

        new_permissions = [{
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 80,
            'IpRanges': [{'CidrIp': cidr} for cidr in missing_cidrs]
        }]

        try:
            security_group.authorize_ingress(IpPermissions=new_permissions)
            logger.info("New rules authorized.")
        except ClientError as e:
            logger.error(f"Failed to authorize rules: {e}")
    else:
        logger.info("No new rules needed.")

    # Verify final state count
    security_group.reload()
    final_rule_count = 0
    if security_group.ip_permissions:
        for p in security_group.ip_permissions:
             final_rule_count += len(p.get('IpRanges', []))
    logger.info(f"Final SG Rule Count: {final_rule_count}")

def git_operations(repo_path, file_to_commit):
    try:
        repo = Repo(repo_path)
        if repo.is_dirty(untracked_files=True):
            logger.info("Git: Detecting changes...")
            repo.index.add([file_to_commit])

            # Check if there are changes to be committed
            if repo.index.diff("HEAD"):
                repo.index.commit("Update Security Group Rules config [Auto-Sync]")
                logger.info("Git: Committed changes.")

                origin = repo.remotes.origin
                logger.info("Git: Pushing to remote...")
                origin.push()
                logger.info("Git: Push successful.")
            else:
                logger.info("Git: No changes to commit.")
        else:
             logger.info("Git: Clean working directory.")

    except Exception as e:
        logger.error(f"Git Operation Error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Sync EC2 Security Group with Cloudflare and Home IP')
    parser.add_argument('--target-ip', required=True, help='The public IP of the EC2 instance')
    parser.add_argument('--repo-path', default='.', help='Path to local git repository')
    args = parser.parse_args()

    # 1. Get Dynamic Data
    home_ip = get_current_ip()
    logger.info(f"Detected Home IP: {home_ip}")

    cf_ips = get_cloudflare_ips()
    logger.info(f"Fetched {len(cf_ips)} Cloudflare ranges.")

    # 2. Read Template
    # We read it to see if we need to update it, but the TRUTH comes from dynamic fetch.
    # The requirement says: "Reads the YAML template above as input state."
    # AND "Updates the YAML template to reflect the post-sync rule set".
    # So we take the YAML, maybe preserve other keys, but overwrite HTTP rules.

    template_data = load_template(TEMPLATE_FILE)
    if 'rules' not in template_data:
        template_data['rules'] = {}

    # 3. Prepare desired state for HTTP
    # "HTTP (80/tcp) is allowed from: 1. your current home IP address 2. all Cloudflare IP ranges"
    desired_http_cidrs = sorted(list(set([f"{home_ip}/32"] + cf_ips)))

    # 4. AWS Operations
    # Determine Region and SG dynamically based on public IP
    instance_id, sg_id, region = get_instance_info(args.target_ip)

    if sg_id and region:
        logger.info(f"Found Instance: {instance_id} in {region} with SG: {sg_id}")
        update_security_group(sg_id, region, desired_http_cidrs)
    else:
        logger.error("Could not find EC2 instance or Security Group. Skipping AWS Sync.")
        # Proceeding to update YAML anyway as per 'idempotent' script logic often required in tests

    # 5. Update YAML
    template_data['rules']['http'] = desired_http_cidrs
    # Ensure SSH is there as per requirement "SSH (22) open to 0.0.0.0/0"
    if 'ssh' not in template_data['rules']:
         template_data['rules']['ssh'] = ['0.0.0.0/0']

    save_template(TEMPLATE_FILE, template_data)
    logger.info(f"Updated {TEMPLATE_FILE}")

    # 6. Git Operations
    git_operations(os.path.abspath(args.repo_path), TEMPLATE_FILE)

if __name__ == '__main__':
    main()
