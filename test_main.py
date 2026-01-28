import unittest
from unittest.mock import patch, MagicMock, mock_open
import sys
import os
import yaml

# Add current directory to path so we can import main
sys.path.append(os.getcwd())

from main import SecurityGroupSync, YAML_FILE

class TestSecurityGroupSync(unittest.TestCase):
    def setUp(self) -> None:
        self.home_ip = "1.2.3.4/32"
        # Patch git.Repo so we don't need a real git repo
        with patch('main.git.Repo'):
            self.syncer = SecurityGroupSync(self.home_ip, dry_run=False)
            self.syncer.repo = MagicMock() # Replace the mock repo instance with a MagicMock we can assert on

    @patch('main.requests.put')
    @patch('main.requests.get')
    def test_get_instance_region(self, mock_get: MagicMock, mock_put: MagicMock) -> None:
        # Mock Token
        mock_put.return_value.status_code = 200
        mock_put.return_value.text = "TOKEN"

        # Mock Region
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "us-east-1"

        region = self.syncer.get_instance_region()
        self.assertEqual(region, "us-east-1")

    @patch('main.requests.get')
    def test_fetch_cloudflare_ips(self, mock_get: MagicMock) -> None:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "success": True,
            "result": {"ipv4_cidrs": ["173.245.48.0/20", "103.21.244.0/22"]}
        }

        self.syncer.fetch_cloudflare_ips()
        self.assertEqual(len(self.syncer.cloudflare_cidrs), 2)
        self.assertIn("173.245.48.0/20", self.syncer.cloudflare_cidrs)

    def test_sync_sg_rules(self) -> None:
        # Setup syncer
        self.syncer.ec2 = MagicMock()
        self.syncer.sg_id = "sg-123"

        # Mock describe_security_groups response (Current state)
        # Existing rules: port 80 from 8.8.8.8/32 (Stale IP that should be removed)
        self.syncer.ec2.describe_security_groups.return_value = {
            'SecurityGroups': [{
                'IpPermissions': [{
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '8.8.8.8/32'}]
                }]
            }]
        }

        # Desired state: Home IP + 1 CF IP
        desired = {self.home_ip, "1.1.1.1/32"}

        self.syncer.sync_sg_rules(desired)

        # Check Revoke called for 8.8.8.8/32
        self.syncer.ec2.revoke_security_group_ingress.assert_called_once()
        call_args = self.syncer.ec2.revoke_security_group_ingress.call_args
        self.assertEqual(call_args[1]['GroupId'], 'sg-123')
        revoked_ranges = [r['CidrIp'] for r in call_args[1]['IpPermissions'][0]['IpRanges']]
        self.assertIn('8.8.8.8/32', revoked_ranges)

        # Check Authorize called
        self.syncer.ec2.authorize_security_group_ingress.assert_called_once()

    def test_update_yaml_file_writes_changes(self) -> None:
        self.syncer.yaml_data = {}
        desired = {"1.1.1.1/32"}

        # Mock file operations
        mock_file = mock_open(read_data="old_content")
        with patch("builtins.open", mock_file):
            self.syncer.update_yaml_file(desired)

        # Check if write was called
        mock_file().write.assert_called()

    def test_update_yaml_file_idempotent(self) -> None:
        self.syncer.yaml_data = {}
        desired = {"1.1.1.1/32"}
        # Pre-calculate expected output
        expected_yml = yaml.dump({'rules': {'http': ['1.1.1.1/32']}}, sort_keys=False)

        # Mock file reading returning the exact content we expect
        mock_file = mock_open(read_data=expected_yml)
        with patch("builtins.open", mock_file):
            self.syncer.update_yaml_file(desired)

        # Write should NOT be called because content is identical
        mock_file().write.assert_not_called()

    def test_git_operations(self) -> None:
        # Mock repo is dirty
        self.syncer.repo.is_dirty.return_value = True

        self.syncer.git_commit_push()

        self.syncer.repo.git.add.assert_called_with(YAML_FILE)
        self.syncer.repo.index.commit.assert_called()
        self.syncer.repo.remotes.origin.push.assert_called()

if __name__ == '__main__':
    unittest.main()
