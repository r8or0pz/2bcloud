# EC2 Security Group Sync

This tool automates the hardening of an AWS EC2 instance's network access. It dynamically syncs the Security Group rules to allow HTTP access only from known Cloudflare IP ranges and a specific Home IP, while preserving SSH access.

## Features

- **Dynamic Discovery**: Automatically detects AWS Region and the relevant Security Group using EC2 Instance Metadata Service (IMDSv2).
- **Targeted Syncing**: Updates only the Security Group allowing SSH (testing/web), ignoring default groups.
- **Cloudflare Integration**: Fetches the latest IPv4 ranges directly from Cloudflare's API.
- **Idempotent**: preventing duplicate rules and unnecessary API calls.
- **GitOps**: Updates a local `security-group.yaml` file with the current state and commits changes to Git.

## Prerequisites

- **Python 3.9+**
- **uv**: This project uses `uv` for dependency management.
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  source $HOME/.local/bin/env
  ```
- **git**: Installed and configured on the instance.
- **IAM Role**: The EC2 instance must have an IAM role with permissions to:
  - `ec2:DescribeSecurityGroups`
  - `ec2:AuthorizeSecurityGroupIngress`
  - `ec2:RevokeSecurityGroupIngress`

## Installation

1.  **Clone the repository** to your EC2 instance:
    ```bash
    git clone <your-repo-url>
    cd 2bcloud
    ```

2.  **Install dependencies**:
    ```bash
    uv sync
    ```

## Configuration

- **Home IP**: The script contains a hardcoded `HOME_IP` constant (Requirement 1.a). Ensure this matches your current public IP address in `main.py` before running.

## Usage

1.  **Run the script**:
    ```bash
    uv run main.py
    ```

    **Dry Run Mode:**
    To preview changes without applying them to AWS or Git:
    ```bash
    uv run main.py --dry-run
    ```

## Testing

The project includes a suite of unit tests to verify core logic (AWS detection, rule calculation, idempotency, etc.).

To run the tests:
```bash
uv run python -m unittest test_main.py
```

## How It Works

1.  **Context Detection**: The script queries the AWS IMDSv2 to find the instance's Region and MAC address.
2.  **SG Selection**: It identifies the Security Group associated with the primary network interface. If multiple groups coexist (e.g., `default` and `testing`), it intelligently selects the one allowing SSH access from `0.0.0.0/0`.
3.  **Fetch Ranges**: It retrieves the latest list of Cloudflare IPv4 CIDRs.
4.  **Sync**:
    - It calculates the difference between the *desired state* (Home IP + Cloudflare) and the *actual state* of the Security Group.
    - Revokes unauthorized HTTP rules.
    - Authorizes missing HTTP rules.
5.  **Persist**: Updates `security-group.yaml` and commits the change to the local Git repository.

## Output

The script provides detailed logging:
- Detected Home IP.
- Detected environment (Region, SG ID).
- Number of Cloudflare ranges found.
- Planned changes (adds/removes).
- Final count of Security Group rules.
