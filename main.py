"""
EC2 Security Group Sync Tool.

This script automates the hardening of an EC2 Security Group by syncing HTTP rules
with a user's home IP and Cloudflare's published IP ranges.

Key Features:
- Determining AWS environment (Region, SG) via IMDSv2.
- Fetching dynamic Cloudflare ranges.
- Idempotent SG updates: only adds/removes differences.
- GitOps: Commits state changes to a local YAML file and pushes to a remote repo.
"""

import os
import sys
import yaml
import requests
import boto3
import git
import argparse
import logging
from datetime import datetime
from typing import Optional, Set

# --- Configuration ---
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- Constants ---
# Requirement 1.a: Your current home/public IP is a constant (CIDR /32)
# REPLACE THIS with your actual IP if running locally or pass it in.
HOME_IP = "94.153.134.142"
HOME_IP_CIDR = f"{HOME_IP}/32"

YAML_FILE = "security-group.yaml"
CLOUDFLARE_API_URL = "https://api.cloudflare.com/client/v4/ips"
EC2_METADATA_URL = "http://169.254.169.254/latest/meta-data"
EC2_METADATA_TOKEN_URL = "http://169.254.169.254/latest/api/token"


class SecurityGroupSync:
    """
    Main class handling the logic for synchronization.
    """
    def __init__(self, home_ip_cidr: str, dry_run: bool = False) -> None:
        """
        Initialize the syncer.
        :param home_ip_cidr: The user's home IP (constant).
        :param dry_run: If True, skip destructive AWS API calls and git pushes.
        """
        self.home_ip_cidr = home_ip_cidr
        self.dry_run = dry_run
        self.ec2 = None
        self.region: Optional[str] = None
        self.sg_id: Optional[str] = None
        self.cloudflare_cidrs: list[str] = []
        self.yaml_data: dict = {}

        # Initialize Git repo
        try:
            self.repo = git.Repo(os.getcwd())
        except git.exc.InvalidGitRepositoryError:
            logger.error("Current directory is not a git repository.")
            sys.exit(1)

    def get_imds_token(self) -> Optional[str]:
        """
        Get IMDSv2 session token.
        Required for subsequent metadata requests on EC2.
        :return: Token string or None.
        """
        try:
            response = requests.put(
                EC2_METADATA_TOKEN_URL,
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                timeout=2
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException:
            return None

    def get_instance_region(self) -> str:
        """
        Determine the current AWS Region.
        Uses IMDS first, falls back to boto3 session (local profile).
        :return: Region name (e.g., 'us-east-1').
        """
        token = self.get_imds_token()
        headers = {"X-aws-ec2-metadata-token": token} if token else {}

        try:
            # Try fetching region directly (standard method)
            region_resp = requests.get(f"{EC2_METADATA_URL}/placement/region", headers=headers, timeout=2)
            if region_resp.status_code == 200:
                return region_resp.text.strip()

            # Fallback to availability zone parsing if region endpoint fails
            az_resp = requests.get(f"{EC2_METADATA_URL}/placement/availability-zone", headers=headers, timeout=2)
            if az_resp.status_code == 200:
                # Region is AZ minus the last character (usually)
                return az_resp.text[:-1]
        except requests.RequestException:
            pass

        # Fallback to boto3 session default if IMDS fails (e.g. running locally with profile)
        session = boto3.session.Session()
        if session.region_name:
            return session.region_name

        logger.error("Could not determine AWS Region dynamically.")
        sys.exit(1)

    def get_instance_sg(self) -> str:
        """
        Identify the target Security Group.
        Queries IMDS for MAC -> SG IDs. If multiple exist,
        filters for the one with SSH access (0.0.0.0/0).
        :return: Security Group ID (e.g., 'sg-12345').
        """
        # Method 1: If running on EC2, get MAC, then SG IDs associated with interface 0
        token = self.get_imds_token()
        headers = {"X-aws-ec2-metadata-token": token} if token else {}

        try:
            # Get MAC directly
            mac_resp = requests.get(f"{EC2_METADATA_URL}/mac", headers=headers, timeout=2)
            if mac_resp.status_code == 200:
                mac = mac_resp.text.strip()

                # Get Security Group IDs associated with this MAC
                sg_resp = requests.get(f"{EC2_METADATA_URL}/network/interfaces/macs/{mac}/security-group-ids", headers=headers, timeout=2)
                if sg_resp.status_code == 200:
                    sg_ids = sg_resp.text.strip().split('\n')
                    if len(sg_ids) == 1:
                        return sg_ids[0]

                    # If multiple SGs, filter for the one allowing SSH from 0.0.0.0/0
                    # This satisfies the requirement to identify the SG based on "Current State"
                    # and avoids hardcoding the ID.
                    logger.info(f"Found multiple Security Groups: {sg_ids}. filtering...")

                    # Need boto3 to inspect them
                    try:
                        resp = self.ec2.describe_security_groups(GroupIds=sg_ids)
                        for sg in resp['SecurityGroups']:
                            for perm in sg['IpPermissions']:
                                if (perm.get('FromPort') == 22 and
                                    perm.get('ToPort') == 22 and
                                    any(r['CidrIp'] == '0.0.0.0/0' for r in perm.get('IpRanges', []))):
                                    logger.info(f"Selected Security Group {sg['GroupId']} (Group Name: {sg['GroupName']}) based on SSH rule.")
                                    return sg['GroupId']
                    except Exception as e:
                        logger.error(f"Error filtering SGs: {e}")
                        # Fallback to the first one if inspection fails
                        return sg_ids[0]

                    # If no match found, fallback to first
                    return sg_ids[0]

        except requests.RequestException:
            pass

        # Method 2: Fallback for local testing or failure
        # For this specific task, if not on EC2, we might fail or require extensive lookup.
        # But per requirements, "must be determined dynamically", usually implying the environment provides it.

        logger.error("Could not determine Security Group ID dynamically (IMDS failed).")
        logger.error("Ensure you are running this script on the target EC2 instance as per requirements.")
        sys.exit(1)

    def fetch_cloudflare_ips(self) -> None:
        """
        Fetch the current list of Cloudflare IPv4 CIDRs from their public API.
        Populates self.cloudflare_cidrs.
        """
        logger.info("Fetching Cloudflare IP ranges...")
        try:
            resp = requests.get(CLOUDFLARE_API_URL, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            if data['success']:
                self.cloudflare_cidrs = data['result']['ipv4_cidrs']
                logger.info(f"Detected {len(self.cloudflare_cidrs)} Cloudflare IPv4 ranges.")
            else:
                logger.error("Cloudflare API reported failure.")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Error fetching Cloudflare IPs: {e}")
            sys.exit(1)

    def read_yaml_config(self) -> None:
        """
        Load the local YAML configuration file to memory.
        """
        if not os.path.exists(YAML_FILE):
            logger.error(f"{YAML_FILE} not found.")
            sys.exit(1)

        with open(YAML_FILE, 'r') as f:
            self.yaml_data = yaml.safe_load(f)
        logger.info("Loaded YAML configuration.")

    def pull_latest_changes(self) -> None:
        """
        Execute git pull to ensure the workspace is up-to-date
        before calculating any changes.
        """
        if self.dry_run:
             return

        try:
            logger.info("Git: Pulling latest changes from origin to ensure clean state...")
            self.repo.remotes.origin.pull()
        except Exception as e:
            logger.warning(f"Git Warning: Initial pull failed: {e}")

    def run(self) -> None:
        """
        Orchestrate the synchronization process.
        """
        # Log the home IP as per acceptance criteria
        logger.info(f"Detected home IP: {self.home_ip_cidr}")

        # Ensure we have the latest code/config from the repo before doing anything
        self.pull_latest_changes()

        # 1. Init AWS Context
        # Note: We retrieve Region first to init boto3 client
        self.region = self.get_instance_region()
        logger.info(f"Detected Region: {self.region}")

        self.ec2 = boto3.client('ec2', region_name=self.region)

        self.sg_id = self.get_instance_sg()
        logger.info(f"Detected Security Group ID: {self.sg_id}")

        # 2. Fetch External Data
        self.fetch_cloudflare_ips()
        self.read_yaml_config()

        # 3. Plan Desired State
        # Requirements:
        # HTTP (80/tcp) allowed from: current home IP + all Cloudflare IP ranges
        desired_http_cidrs = set(self.cloudflare_cidrs)
        desired_http_cidrs.add(self.home_ip_cidr)

        # 4. Sync Security Group
        logger.info(f"Syncing Security Group {self.sg_id}...")
        self.sync_sg_rules(desired_http_cidrs)

        # 5. Update YAML
        self.update_yaml_file(desired_http_cidrs)

        # 6. Git Operations
        self.git_commit_push()

    def sync_sg_rules(self, desired_cidrs: Set[str]) -> None:
        """
        Calculate and apply the difference between desired and actual SG rules.
        :param desired_cidrs: Set of IPv4 CIDRs that should be allowed on port 80.
        """
        try:
            response = self.ec2.describe_security_groups(GroupIds=[self.sg_id])
            sg_permissions = response['SecurityGroups'][0]['IpPermissions']
        except Exception as e:
            logger.error(f"Error describing security group: {e}")
            sys.exit(1)

        # Parse existing HTTP rules
        existing_cidrs = set()
        for perm in sg_permissions:
            # Check if rule covers port 80
            from_port = perm.get('FromPort')
            to_port = perm.get('ToPort')
            ip_proto = perm.get('IpProtocol')

            if ip_proto == 'tcp' and from_port == 80 and to_port == 80:
                for ip_range in perm.get('IpRanges', []):
                    existing_cidrs.add(ip_range['CidrIp'])

        # Calculate Diff
        to_authorize = desired_cidrs - existing_cidrs
        to_revoke = existing_cidrs - desired_cidrs

        logger.info(f"Planned changes: +{len(to_authorize)} adds, -{len(to_revoke)} removes.")

        # Apply Revocations
        if to_revoke:
            if self.dry_run:
                logger.info(f"Revoking {len(to_revoke)} rules... (SKIPPED - DRY RUN)")
            else:
                logger.info(f"Revoking {len(to_revoke)} rules...")
                try:
                    self.ec2.revoke_security_group_ingress(
                        GroupId=self.sg_id,
                        IpPermissions=[{
                            'IpProtocol': 'tcp',
                            'FromPort': 80,
                            'ToPort': 80,
                            'IpRanges': [{'CidrIp': cidr} for cidr in to_revoke]
                        }]
                    )
                except Exception as e:
                    logger.error(f"Error revoking rules: {e}")

        # Apply Authorizations
        if to_authorize:
            if self.dry_run:
                logger.info(f"Authorizing {len(to_authorize)} rules... (SKIPPED - DRY RUN)")
            else:
                logger.info(f"Authorizing {len(to_authorize)} rules...")
                try:
                    self.ec2.authorize_security_group_ingress(
                        GroupId=self.sg_id,
                        IpPermissions=[{
                            'IpProtocol': 'tcp',
                            'FromPort': 80,
                            'ToPort': 80,
                            'IpRanges': [{'CidrIp': cidr} for cidr in to_authorize]
                        }]
                    )
                except Exception as e:
                    logger.error(f"Error authorizing rules: {e}")

        # Verify Final State & Log Count
        try:
            response = self.ec2.describe_security_groups(GroupIds=[self.sg_id])
            sg = response['SecurityGroups'][0]
            current_rule_count = 0
            for perm in sg['IpPermissions']:
                # Count all ingress rules (IPv4 ranges + IPv6 ranges + User Groups)
                current_rule_count += len(perm.get('IpRanges', []))
                current_rule_count += len(perm.get('UserIdGroupPairs', []))
                current_rule_count += len(perm.get('Ipv6Ranges', []))

            logger.info(f"Final SG rule count: {current_rule_count}")
        except Exception as e:
             logger.error(f"Error fetching final rule count: {e}")

    def update_yaml_file(self, desired_cidrs: Set[str]) -> None:
        """
        Update the local security-group.yaml file with the new rule set.
        Is idempotent - only writes if content changes.
        :param desired_cidrs: Set of IPv4 CIDRs to write.
        """

        # Modify the in-memory structure regardless of dry-run to show what WOULD happen
        if 'rules' not in self.yaml_data:
            self.yaml_data['rules'] = {}

        sorted_cidrs = sorted(list(desired_cidrs))
        self.yaml_data['rules']['http'] = sorted_cidrs

        # Generate the new YAML string
        new_yaml_content = yaml.dump(self.yaml_data, sort_keys=False)

        if self.dry_run:
            logger.info("Skipping YAML update (DRY RUN). Expected YAML content:")
            print("\n" + new_yaml_content + "\n")
            return

        # Check if file has changed to avoid unnecessary writes/logs
        try:
            with open(YAML_FILE, 'r') as f:
                current_content = f.read()
            if current_content == new_yaml_content:
                logger.info(f"{YAML_FILE} is already up-to-date.")
                return
        except FileNotFoundError:
            pass # File doesn't exist, so we must write it

        with open(YAML_FILE, 'w') as f:
            f.write(new_yaml_content)
        logger.info(f"Updated {YAML_FILE}.")

    def git_commit_push(self) -> None:
        """
        Commit changes to the local repo and push to the remote origin.
        Uses the 'is_dirty' check to avoid empty commits.
        """

        if self.dry_run:
             logger.info("Git operations disabled (DRY RUN).")
             return

        # Note: We already pulled at the start of run().
        # But if the execution took a long time, we might want to pull again here if we implemented complex merging logic.
        # For this assignment, assuming the repo is only touched by this script, the initial pull is sufficient.

        if self.repo.is_dirty(untracked_files=True):
            logger.info("Git: Changes detected. Committing...")
            try:
                self.repo.git.add(YAML_FILE)
                # Check if there are changes to commit
                # Note: is_dirty checks working tree/index against HEAD.
                if self.repo.is_dirty() or self.repo.index.diff(self.repo.head.commit):
                    self.repo.index.commit("Auto-update: Sync EC2 Security Group rules")
                    logger.info("Git: Commit created.")

                    logger.info("Git: Pushing to origin...")
                    self.repo.remotes.origin.push()
                    logger.info("Git: Push successful.")
                else:
                    logger.info("Git: No changes after add.")
            except Exception as e:
                logger.error(f"Git Error: {e}")
        else:
            logger.info("Git: No changes to commit.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync EC2 Security Group rules with Cloudflare IPs.")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without modifying AWS Security Groups or Git.")
    args = parser.parse_args()

    logger.info(f"Starting Security Group Sync. Home IP (Code Config): {HOME_IP_CIDR}")
    if args.dry_run:
        logger.info("Running in DRY RUN mode.")

    syncer = SecurityGroupSync(HOME_IP_CIDR, dry_run=args.dry_run)
    syncer.run()
