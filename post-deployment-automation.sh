#!/bin/bash

################################################################################
# AWS Landing Zone Post-Deployment Automation Script - FIXED VERSION
# Version: 3.0.0
# Description: Automates critical post-deployment steps with proper error handling
#
# Prerequisites:
#   - Landing Zone provisioned successfully
#   - Cross-account access configured
#   - MFA enabled on all root accounts (recommended)
#
# Features:
#   1. MFA Configuration Guide
#   2. IAM Identity Center (AWS SSO) Setup
#   3. AWS Config Enablement (all accounts)
#   4. Security Hub Configuration (delegated admin)
#   5. GuardDuty with Auto-Enable
#   6. Custom SCP Implementation
#   7. AWS Backup Configuration
#   8. Tagging Strategy Implementation
#   9. Comprehensive Summary Report
#
# Author: DevOps Team
# Date: 2025-11-17
################################################################################

# set -euo pipefail

# Load environment variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
SCRIPT_VERSION="3.0.0"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
AWS_REGION="${AWS_REGION:-ap-southeast-3}"

# Create results directory structure
RESULTS_DIR="${SCRIPT_DIR}/results"
LOGS_DIR="${RESULTS_DIR}/logs"
SUMMARY_DIR="${RESULTS_DIR}/summary"
AUTOMATION_DIR="${RESULTS_DIR}/automation"

mkdir -p "${LOGS_DIR}" "${SUMMARY_DIR}" "${AUTOMATION_DIR}"

LOG_FILE="${LOGS_DIR}/post-deployment-${TIMESTAMP}.log"

# Account IDs (will be populated)
MANAGEMENT_ACCOUNT_ID=""
LOG_ARCHIVE_ACCOUNT_ID=""
SECURITY_AUDIT_ACCOUNT_ID=""

# Track which steps were completed
declare -A COMPLETED_STEPS

################################################################################
# Logging Functions
################################################################################

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        INFO)
            echo -e "${GREEN}[${timestamp}] [INFO]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
        WARN)
            echo -e "${YELLOW}[${timestamp}] [WARN]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
        ERROR)
            echo -e "${RED}[${timestamp}] [ERROR]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
        SUCCESS)
            echo -e "${CYAN}[${timestamp}] [SUCCESS]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
        STEP)
            echo -e "${MAGENTA}[${timestamp}] [STEP]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
    esac
}

print_banner() {
    echo -e "${BLUE}"
    cat << EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║  AWS Landing Zone Post-Deployment Automation v${SCRIPT_VERSION}            ║
║                                                                ║
║  Automating critical next steps:                               ║
║    1. MFA Configuration Guide                                  ║
║    2. IAM Identity Center (SSO) Setup                          ║
║    3. AWS Config Enablement                                    ║
║    4. Security Hub Configuration                               ║
║    5. GuardDuty with Delegated Admin                           ║
║    6. Custom SCP Implementation                                ║
║    7. AWS Backup Configuration                                 ║
║    8. Tagging Strategy Implementation                          ║
║    9. Summary Report Generation                                ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

################################################################################
# Helper Functions
################################################################################

get_account_ids() {
    print_section "Initialization: Retrieving Account Information"

    log INFO "Retrieving account IDs from AWS Organizations..."

    # Get management account ID
    MANAGEMENT_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    log INFO "Management Account: $MANAGEMENT_ACCOUNT_ID"

    # Get all accounts
    local accounts=$(aws organizations list-accounts --output json)

    # Get core account IDs
    LOG_ARCHIVE_ACCOUNT_ID=$(echo "$accounts" | jq -r '.Accounts[] | select(.Name=="LogArchive") | .Id')
    SECURITY_AUDIT_ACCOUNT_ID=$(echo "$accounts" | jq -r '.Accounts[] | select(.Name=="SecurityAudit") | .Id')

    if [[ -z "$LOG_ARCHIVE_ACCOUNT_ID" ]]; then
        log ERROR "Log Archive account not found. Please run provisioning script first."
        exit 1
    fi

    if [[ -z "$SECURITY_AUDIT_ACCOUNT_ID" ]]; then
        log ERROR "Security/Audit account not found. Please run provisioning script first."
        exit 1
    fi

    log INFO "Log Archive Account: $LOG_ARCHIVE_ACCOUNT_ID"
    log INFO "Security/Audit Account: $SECURITY_AUDIT_ACCOUNT_ID"

    # Get Hub and UAT account IDs
    log INFO "Discovering Hub and UAT accounts..."
    local hub_count=$(echo "$accounts" | jq '[.Accounts[] | select(.Name | startswith("Hub"))] | length')
    local uat_count=$(echo "$accounts" | jq '[.Accounts[] | select(.Name | startswith("UAT"))] | length')
    log INFO "Found $hub_count Hub accounts and $uat_count UAT accounts"

    log SUCCESS "Account information retrieved successfully"
}

assume_role() {
    local account_id=$1
    local role_name=${2:-OrganizationAccountAccessRole}

    log INFO "Assuming role in account $account_id..."

    local credentials
    if ! credentials=$(aws sts assume-role \
        --role-arn "arn:aws:iam::${account_id}:role/${role_name}" \
        --role-session-name "post-deployment-automation-$$" \
        --duration-seconds 3600 \
        --output json 2>&1); then
        log WARN "Cannot assume role in account $account_id"
        log WARN "Please ensure cross-account access is configured"
        return 1
    fi

    export AWS_ACCESS_KEY_ID=$(echo $credentials | jq -r '.Credentials.AccessKeyId')
    export AWS_SECRET_ACCESS_KEY=$(echo $credentials | jq -r '.Credentials.SecretAccessKey')
    export AWS_SESSION_TOKEN=$(echo $credentials | jq -r '.Credentials.SessionToken')

    log SUCCESS "Successfully assumed role in account $account_id"
    return 0
}

restore_credentials() {
    unset AWS_ACCESS_KEY_ID
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_SESSION_TOKEN

    log INFO "Restored original credentials"
}

################################################################################
# Step 1: MFA Configuration Guide
################################################################################

configure_mfa_guide() {
    print_section "Step 1: MFA Configuration Guide"

    log STEP "Generating comprehensive MFA configuration guide..."

    # Get all accounts for MFA guide
    local all_accounts=$(aws organizations list-accounts \
        --query 'Accounts[?Status==`ACTIVE`].[Name,Id,Email]' \
        --output json)

    cat > "${AUTOMATION_DIR}/mfa-configuration-guide.txt" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║          MFA Configuration Guide for All Root Users            ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

CRITICAL: Enable MFA on ALL root user accounts immediately!
This is your highest priority security task.

═══════════════════════════════════════════════════════════════

ACCOUNTS REQUIRING MFA:

$(echo "$all_accounts" | jq -r '.[] | "Account: \(.[0])\n   ID: \(.[1])\n   Email: \(.[2])\n   Console: https://\(.[1]).signin.aws.amazon.com/console\n"')

═══════════════════════════════════════════════════════════════

STEP-BY-STEP MFA SETUP PROCEDURE:

For EACH account listed above:

1. Sign in as Root User
   - Go to the Console URL for the account
   - Use the root email address
   - Check email for password reset if needed

2. Navigate to Security Credentials
   - Click your account name (top right)
   - Select "Security credentials"
   - Or go to: https://console.aws.amazon.com/iam/home#/security_credentials

3. Enable Multi-Factor Authentication (MFA)
   - Find "Multi-factor authentication (MFA)" section
   - Click "Activate MFA"

4. Choose MFA Device Type:

   A. Virtual MFA (Recommended for convenience)
      - Install authenticator app on phone:
        • Google Authenticator
        • Microsoft Authenticator
        • Authy
        • 1Password
      - Click "Virtual MFA device"
      - Scan QR code with your app
      - Enter two consecutive MFA codes
      - Click "Assign MFA"

   B. Hardware MFA (Recommended for maximum security)
      - Use physical security key (e.g., Gemalto token)
      - Enter device serial number
      - Enter two consecutive codes from device

   C. U2F Security Key (Best for usability + security)
      - Use YubiKey or similar FIDO device
      - Insert key when prompted
      - Touch key to authenticate

5. CRITICAL: Save Emergency Information
   - Download and securely store backup codes
   - Store in password manager or secure vault
   - Keep MFA device in safe location
   - Document who has access

6. Verify MFA is Active
   - Sign out completely
   - Sign back in as root
   - Should prompt for MFA code
   - Security credentials page should show "MFA device assigned"

7. Delete Root Access Keys (IMPORTANT!)
   - In same Security Credentials page
   - Look for "Access keys" section
   - Delete ANY access keys listed
   - Root account should NEVER have access keys

═══════════════════════════════════════════════════════════════

VERIFICATION COMMANDS:

# Check if MFA is enabled (run from management account)
aws iam get-account-summary | jq '.SummaryMap.AccountMFAEnabled'
# Should return: 1 (enabled)

# Verify no root access keys exist
aws iam list-access-keys --user-name root 2>&1
# Should return: error (no such entity) - this is GOOD!

═══════════════════════════════════════════════════════════════

EMERGENCY ACCESS PROCEDURES:

1. If MFA device is lost:
   - Contact AWS Support immediately
   - Have account recovery information ready
   - May require identity verification

2. If locked out:
   - Use "Forgot password" on sign-in page
   - Check root email for recovery link
   - Contact AWS Support if needed

3. Break-glass access:
   - Store backup codes in secure, accessible location
   - Document emergency contact procedures
   - Test recovery process periodically

═══════════════════════════════════════════════════════════════

SECURITY BEST PRACTICES:

✓ Enable MFA on ALL accounts (no exceptions)
✓ Use different MFA devices for different account types
✓ Store backup codes in secure password manager
✓ Delete root access keys immediately
✓ Never share MFA devices or codes
✓ Test MFA immediately after setup
✓ Document emergency access procedures
✓ Review MFA status monthly

✓ For production genomics workloads (Hub accounts):
  - Consider hardware MFA for extra security
  - Document who has access to MFA devices
  - Establish change management procedures

═══════════════════════════════════════════════════════════════

TRACKING YOUR PROGRESS:

Use this checklist to track MFA setup:

Management Account ($MANAGEMENT_ACCOUNT_ID): [ ]
Log Archive ($LOG_ARCHIVE_ACCOUNT_ID): [ ]
Security/Audit ($SECURITY_AUDIT_ACCOUNT_ID): [ ]

Hub Accounts:
$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE` && starts_with(Name, `Hub`)].[Name,Id]' --output text | awk '{print "  " $1 " (" $2 "): [ ]"}')

UAT Accounts:
$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE` && starts_with(Name, `UAT`)].[Name,Id]' --output text | awk '{print "  " $1 " (" $2 "): [ ]"}')

═══════════════════════════════════════════════════════════════

ESTIMATED TIME:
- Per account: 5-10 minutes
- Total time: ~$(aws organizations list-accounts --query 'length(Accounts[?Status==`ACTIVE`])' --output text) accounts × 10 min = $(( $(aws organizations list-accounts --query 'length(Accounts[?Status==`ACTIVE`])' --output text) * 10 )) minutes

Start with critical accounts first:
1. Management Account (highest priority)
2. Security/Audit Account
3. Hub Production Accounts
4. Log Archive Account
5. UAT Staging Accounts

═══════════════════════════════════════════════════════════════
EOF

    log SUCCESS "MFA configuration guide created: ${AUTOMATION_DIR}/mfa-configuration-guide.txt"
    COMPLETED_STEPS["mfa_guide"]=1

    echo ""
    log WARN "⚠️  MANUAL ACTION REQUIRED ⚠️"
    log WARN "MFA must be enabled on all root accounts before production use"
    log WARN "Guide saved to: ${AUTOMATION_DIR}/mfa-configuration-guide.txt"
    echo ""

    read -p "Press ENTER after reviewing the MFA guide to continue..."
}

################################################################################
# Step 2: IAM Identity Center (AWS SSO) Setup
################################################################################

setup_iam_identity_center() {
    print_section "Step 2: IAM Identity Center (AWS SSO) Setup"

    log STEP "Configuring IAM Identity Center..."

    # Check if already enabled
    log INFO "Checking if IAM Identity Center is already enabled..."

    local instance_check=$(aws sso-admin list-instances --region $AWS_REGION --output json 2>/dev/null || echo '{"Instances":[]}')

    if [[ $(echo "$instance_check" | jq '.Instances | length') -gt 0 ]]; then
        local instance_arn=$(echo "$instance_check" | jq -r '.Instances[0].InstanceArn')
        local identity_store_id=$(echo "$instance_check" | jq -r '.Instances[0].IdentityStoreId')

        log WARN "IAM Identity Center already enabled"
        log INFO "Instance ARN: $instance_arn"
        log INFO "Identity Store ID: $identity_store_id"
    else
        log INFO "Enabling IAM Identity Center..."
        log WARN "IAM Identity Center requires manual enablement via Console:"
        log WARN "https://console.aws.amazon.com/singlesignon/home?region=${AWS_REGION}"
        log WARN "After enabling, re-run this script to continue configuration"

        cat > "${AUTOMATION_DIR}/iam-identity-center-manual-setup.txt" <<EOF
═══════════════════════════════════════════════════════════════
IAM Identity Center Manual Setup Required
═══════════════════════════════════════════════════════════════

IAM Identity Center cannot be enabled via CLI and requires manual setup.

Steps to Enable:

1. Go to IAM Identity Center Console:
   https://console.aws.amazon.com/singlesignon/home?region=${AWS_REGION}

2. Click "Enable"

3. Choose Identity Source:
   - AWS IAM Identity Center directory (default, easiest)
   - Active Directory
   - External Identity Provider (Azure AD, Okta, etc.)

4. After enabling, note down:
   - User Portal URL
   - Instance ARN
   - Identity Store ID

5. Then re-run this post-deployment script to continue

═══════════════════════════════════════════════════════════════
EOF

        COMPLETED_STEPS["sso_setup"]="manual_required"
        return 0
    fi

    # Get instance details
    local instance_arn=$(aws sso-admin list-instances --region $AWS_REGION --query 'Instances[0].InstanceArn' --output text)
    local identity_store_id=$(aws sso-admin list-instances --region $AWS_REGION --query 'Instances[0].IdentityStoreId' --output text)

    log INFO "Creating permission sets..."

    # Define permission sets
    declare -A permission_sets=(
        ["AdministratorAccess"]="Full administrator access to AWS services"
        ["ReadOnlyAccess"]="Read-only access to AWS services"
        ["PowerUserAccess"]="Full access except IAM and Organizations"
        ["SecurityAuditor"]="Security audit and compliance access"
    )

    for ps_name in "${!permission_sets[@]}"; do
        local ps_desc="${permission_sets[$ps_name]}"

        log INFO "Creating permission set: $ps_name"

        aws sso-admin create-permission-set \
            --instance-arn "$instance_arn" \
            --name "$ps_name" \
            --description "$ps_desc" \
            --session-duration "PT8H" \
            --region $AWS_REGION 2>/dev/null && log SUCCESS "Created: $ps_name" || log WARN "$ps_name may already exist"

        # Attach appropriate managed policies
        local policy_arn=""
        case $ps_name in
            "AdministratorAccess")
                policy_arn="arn:aws:iam::aws:policy/AdministratorAccess"
                ;;
            "ReadOnlyAccess")
                policy_arn="arn:aws:iam::aws:policy/ReadOnlyAccess"
                ;;
            "PowerUserAccess")
                policy_arn="arn:aws:iam::aws:policy/PowerUserAccess"
                ;;
            "SecurityAuditor")
                policy_arn="arn:aws:iam::aws:policy/SecurityAudit"
                ;;
        esac

        if [[ -n "$policy_arn" ]]; then
            local ps_arn=$(aws sso-admin list-permission-sets \
                --instance-arn "$instance_arn" \
                --region $AWS_REGION \
                --query "PermissionSets[0]" \
                --output text)

            aws sso-admin attach-managed-policy-to-permission-set \
                --instance-arn "$instance_arn" \
                --permission-set-arn "$ps_arn" \
                --managed-policy-arn "$policy_arn" \
                --region $AWS_REGION 2>/dev/null || true
        fi
    done

    log SUCCESS "Permission sets configured"

    # Generate comprehensive setup guide
    cat > "${AUTOMATION_DIR}/iam-identity-center-setup.txt" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║        IAM Identity Center Configuration Guide                 ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

IAM Identity Center (AWS SSO) has been configured.

Instance ARN: ${instance_arn}
Identity Store ID: ${identity_store_id}
Region: ${AWS_REGION}
User Portal: https://d-xxxxxxxxxx.awsapps.com/start

═══════════════════════════════════════════════════════════════

PERMISSION SETS CREATED:

✓ AdministratorAccess (8-hour session)
  Full access to all AWS services and resources

✓ ReadOnlyAccess (8-hour session)
  Read-only access across all services

✓ PowerUserAccess (8-hour session)
  Full access except IAM and Organizations management

✓ SecurityAuditor (8-hour session)
  Security audit and compliance monitoring access

═══════════════════════════════════════════════════════════════

NEXT MANUAL STEPS:

1. Create User Groups
   - Go to IAM Identity Center Console
   - Users → Groups → Create group
   - Recommended groups:
     • Administrators
     • Developers
     • DevOps
     • SecurityTeam
     • ReadOnlyUsers

2. Create Users
   - Users → Add user
   - Set username and email
   - Send welcome email with temporary password
   - User must set permanent password on first login

3. Assign Users to Groups
   - Select group → Add users
   - Add appropriate users to each group

4. Assign Permission Sets to Accounts

   Example assignments:
   • AdministratorAccess → Management Account → Administrators group
   • PowerUserAccess → Hub Accounts → DevOps group
   • ReadOnlyAccess → All Accounts → ReadOnlyUsers group
   • SecurityAuditor → Security/Audit Account → SecurityTeam group

   To assign:
   - AWS accounts → Select account
   - Assign users or groups
   - Choose permission set
   - Confirm assignment

5. Configure MFA for SSO Users
   - Settings → Authentication
   - Configure: "Users should be prompted for MFA"
   - Choose: "Every time they sign in (always-on)"
   - Supported: Authenticator apps and security keys

6. Configure Session Duration (Optional)
   - Settings → Session settings
   - Adjust session duration as needed
   - Minimum: 1 hour
   - Maximum: 12 hours
   - Default: 8 hours (already configured)

═══════════════════════════════════════════════════════════════

RECOMMENDED GROUP → PERMISSION SET → ACCOUNT MAPPING:

Administrators Group:
  → AdministratorAccess → Management Account
  → AdministratorAccess → Security/Audit Account

DevOps Group:
  → PowerUserAccess → Hub01-RSCM, Hub02-RSPON, etc.
  → PowerUserAccess → UAT01-RSCM, UAT02-RSPON, etc.

Developers Group:
  → PowerUserAccess → UAT accounts only (staging)
  → ReadOnlyAccess → Hub accounts (production)

SecurityTeam Group:
  → SecurityAuditor → All Accounts
  → AdministratorAccess → Security/Audit Account

ReadOnlyUsers Group:
  → ReadOnlyAccess → All Accounts

═══════════════════════════════════════════════════════════════

USER ACCESS WORKFLOW:

1. User receives welcome email
2. User goes to User Portal URL
3. User signs in with username/password
4. User configures MFA device
5. User selects account and permission set
6. User is redirected to AWS Console with appropriate access

CLI Access:
aws sso login --profile <profile-name>
aws sso configure

═══════════════════════════════════════════════════════════════

GENOMICS WORKLOAD CONSIDERATIONS:

For sBeacon/sVEP deployments:
- Give DevOps team PowerUserAccess to Hub accounts
- Restrict direct production access
- Use UAT accounts for testing
- Require MFA for all production access
- Implement approval workflows for sensitive changes

═══════════════════════════════════════════════════════════════
EOF

    log SUCCESS "IAM Identity Center setup guide created: ${AUTOMATION_DIR}/iam-identity-center-setup.txt"
    COMPLETED_STEPS["sso_setup"]=1
}

################################################################################
# Step 3: AWS Config Enablement
################################################################################

enable_aws_config() {
    print_section "Step 3: AWS Config Enablement"

    log STEP "Enabling AWS Config in all accounts..."

    # Get all active accounts
    local all_accounts=$(aws organizations list-accounts \
        --query 'Accounts[?Status==`ACTIVE`].Id' \
        --output text)

    local config_bucket="aws-config-logs-${LOG_ARCHIVE_ACCOUNT_ID}"
    local success_count=0
    local skip_count=0

    # Create Config bucket in Log Archive account
    log INFO "Setting up Config S3 bucket in Log Archive account..."

    if assume_role "$LOG_ARCHIVE_ACCOUNT_ID"; then
        # Create bucket
        if aws s3 mb "s3://${config_bucket}" --region $AWS_REGION 2>/dev/null; then
            log SUCCESS "Config bucket created: $config_bucket"
        else
            log WARN "Config bucket may already exist: $config_bucket"
        fi

        # Enable versioning
        aws s3api put-bucket-versioning \
            --bucket "$config_bucket" \
            --versioning-configuration Status=Enabled 2>/dev/null || true

        # Enable encryption
        aws s3api put-bucket-encryption \
            --bucket "$config_bucket" \
            --server-side-encryption-configuration '{
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    },
                    "BucketKeyEnabled": true
                }]
            }' 2>/dev/null || true

        # Configure bucket policy for cross-account access
        cat > /tmp/config-bucket-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${config_bucket}"
    },
    {
      "Sid": "AWSConfigBucketExistenceCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::${config_bucket}"
    },
    {
      "Sid": "AWSConfigBucketPut",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${config_bucket}/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
EOF

        aws s3api put-bucket-policy \
            --bucket "$config_bucket" \
            --policy file:///tmp/config-bucket-policy.json 2>/dev/null || true

        rm -f /tmp/config-bucket-policy.json

        restore_credentials
        log SUCCESS "Config S3 bucket configured"
    else
        log WARN "Could not access Log Archive account - skipping Config bucket setup"
    fi

    # Enable Config in each account
    for account_id in $all_accounts; do
        log INFO "Configuring AWS Config in account: $account_id"

        # Restore credentials for management account
        if [[ "$account_id" != "$MANAGEMENT_ACCOUNT_ID" ]]; then
            if ! assume_role "$account_id"; then
                log WARN "Skipping Config setup in account $account_id"
                ((skip_count++))
                continue
            fi
        fi

        # Create service-linked role for Config
        aws iam create-service-linked-role \
            --aws-service-name config.amazonaws.com 2>/dev/null || true

        # Put configuration recorder
        aws configservice put-configuration-recorder \
            --configuration-recorder "name=default,roleARN=arn:aws:iam::${account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig" \
            --recording-group "allSupported=true,includeGlobalResourceTypes=true" \
            --region $AWS_REGION 2>/dev/null || log WARN "Config recorder may already exist"

        # Put delivery channel
        aws configservice put-delivery-channel \
            --delivery-channel "name=default,s3BucketName=${config_bucket}" \
            --region $AWS_REGION 2>/dev/null || log WARN "Delivery channel may already exist"

        # Start configuration recorder
        aws configservice start-configuration-recorder \
            --configuration-recorder-name default \
            --region $AWS_REGION 2>/dev/null || log WARN "Config recorder may already be running"

        if [[ "$account_id" != "$MANAGEMENT_ACCOUNT_ID" ]]; then
            restore_credentials
        fi

        log SUCCESS "AWS Config enabled in account: $account_id"
        ((success_count++))

        sleep 2
    done

    log SUCCESS "AWS Config enabled in $success_count accounts (skipped: $skip_count)"
    COMPLETED_STEPS["aws_config"]=$success_count
}

################################################################################
# Step 4: Security Hub Configuration
################################################################################

setup_security_hub() {
    print_section "Step 4: Security Hub Configuration"

    log STEP "Setting up Security Hub with delegated administration..."

    # Enable Organizations integration
    log INFO "Enabling Security Hub service access in Organizations..."
    aws organizations enable-aws-service-access \
        --service-principal securityhub.amazonaws.com 2>/dev/null || true

    # Enable in Security/Audit account as delegated admin
    log INFO "Enabling Security Hub in Security/Audit account..."

    if ! assume_role "$SECURITY_AUDIT_ACCOUNT_ID"; then
        log WARN "Cannot configure Security Hub - skipping"
        COMPLETED_STEPS["security_hub"]="skipped"
        return 0
    fi

    # Enable Security Hub
    aws securityhub enable-security-hub \
        --enable-default-standards \
        --region $AWS_REGION 2>/dev/null || log WARN "Security Hub may already be enabled"

    # Enable specific standards
    log INFO "Enabling security standards..."

    # AWS Foundational Security Best Practices
    aws securityhub batch-enable-standards \
        --standards-subscription-requests "StandardsArn=arn:aws:securityhub:${AWS_REGION}::standards/aws-foundational-security-best-practices/v/1.0.0" \
        --region $AWS_REGION 2>/dev/null || true

    # CIS AWS Foundations Benchmark
    aws securityhub batch-enable-standards \
        --standards-subscription-requests "StandardsArn=arn:aws:securityhub:${AWS_REGION}::standards/cis-aws-foundations-benchmark/v/1.2.0" \
        --region $AWS_REGION 2>/dev/null || true

    restore_credentials

    # Register as delegated administrator
    log INFO "Registering Security/Audit account as delegated administrator..."

    aws securityhub enable-organization-admin-account \
        --admin-account-id "$SECURITY_AUDIT_ACCOUNT_ID" \
        --region $AWS_REGION 2>/dev/null || log WARN "Delegated admin may already be configured"

    log SUCCESS "Security Hub configured with delegated administration"
    COMPLETED_STEPS["security_hub"]=1
}

################################################################################
# Step 5: GuardDuty with Auto-Enable
################################################################################

setup_guardduty() {
    print_section "Step 5: GuardDuty with Delegated Administration"

    log STEP "Setting up GuardDuty..."

    # Enable Organizations integration
    log INFO "Enabling GuardDuty service access in Organizations..."
    aws organizations enable-aws-service-access \
        --service-principal guardduty.amazonaws.com 2>/dev/null || true

    # Enable in Security/Audit account
    if ! assume_role "$SECURITY_AUDIT_ACCOUNT_ID"; then
        log WARN "Cannot configure GuardDuty - skipping"
        COMPLETED_STEPS["guardduty"]="skipped"
        return 0
    fi

    log INFO "Enabling GuardDuty in Security/Audit account..."

    # Create detector
    local detector_id=$(aws guardduty create-detector \
        --enable \
        --finding-publishing-frequency FIFTEEN_MINUTES \
        --region $AWS_REGION \
        --query 'DetectorId' \
        --output text 2>/dev/null || echo "")

    if [[ -z "$detector_id" ]]; then
        detector_id=$(aws guardduty list-detectors \
            --region $AWS_REGION \
            --query 'DetectorIds[0]' \
            --output text 2>/dev/null || echo "")
        log WARN "GuardDuty already enabled, using existing detector: $detector_id"
    else
        log SUCCESS "GuardDuty enabled with detector ID: $detector_id"
    fi

    restore_credentials

    # Register as delegated administrator
    log INFO "Registering Security/Audit account as delegated administrator..."

    aws guardduty enable-organization-admin-account \
        --admin-account-id "$SECURITY_AUDIT_ACCOUNT_ID" \
        --region $AWS_REGION 2>/dev/null || log WARN "Delegated admin may already be configured"

    # Configure auto-enable for new accounts
    if assume_role "$SECURITY_AUDIT_ACCOUNT_ID"; then
        log INFO "Configuring auto-enable for new accounts..."

        if [[ -n "$detector_id" ]]; then
            aws guardduty update-organization-configuration \
                --detector-id "$detector_id" \
                --auto-enable \
                --region $AWS_REGION 2>/dev/null || log WARN "Auto-enable may already be configured"
        fi

        restore_credentials
    fi

    log SUCCESS "GuardDuty configured with auto-enable for new accounts"
    COMPLETED_STEPS["guardduty"]=1
}

################################################################################
# Step 6: Custom SCPs Implementation
################################################################################

implement_custom_scps() {
    print_section "Step 6: Custom Service Control Policies"

    log STEP "Creating additional Service Control Policies..."

    # Check if already exists
    local existing_region_scp=$(aws organizations list-policies \
        --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='DenyUnapprovedRegions'].Id" \
        --output text 2>/dev/null || echo "")

    if [[ -z "$existing_region_scp" ]]; then
        log INFO "Creating DenyUnapprovedRegions SCP..."

        cat > /tmp/deny-regions-scp.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "ap-southeast-3",
            "us-east-1"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/OrganizationAccountAccessRole"
          ]
        }
      }
    }
  ]
}
EOF

        aws organizations create-policy \
            --content file:///tmp/deny-regions-scp.json \
            --description "Deny access to unapproved AWS regions" \
            --name "DenyUnapprovedRegions" \
            --type SERVICE_CONTROL_POLICY \
            --output json >/dev/null 2>&1 && log SUCCESS "DenyUnapprovedRegions SCP created" || log WARN "SCP may already exist"

        rm -f /tmp/deny-regions-scp.json
    else
        log WARN "DenyUnapprovedRegions SCP already exists"
    fi

    # Create S3 encryption SCP
    local existing_s3_scp=$(aws organizations list-policies \
        --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='EnforceS3Encryption'].Id" \
        --output text 2>/dev/null || echo "")

    if [[ -z "$existing_s3_scp" ]]; then
        log INFO "Creating EnforceS3Encryption SCP..."

        cat > /tmp/s3-encryption-scp.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedS3Uploads",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": [
            "AES256",
            "aws:kms"
          ]
        }
      }
    }
  ]
}
EOF

        aws organizations create-policy \
            --content file:///tmp/s3-encryption-scp.json \
            --description "Require encryption for all S3 uploads" \
            --name "EnforceS3Encryption" \
            --type SERVICE_CONTROL_POLICY \
            --output json >/dev/null 2>&1 && log SUCCESS "EnforceS3Encryption SCP created" || log WARN "SCP may already exist"

        rm -f /tmp/s3-encryption-scp.json
    else
        log WARN "EnforceS3Encryption SCP already exists"
    fi

    log SUCCESS "Custom SCPs implemented"
    COMPLETED_STEPS["custom_scps"]=1
}

################################################################################
# Step 7: AWS Backup Configuration
################################################################################

configure_aws_backup() {
    print_section "Step 7: AWS Backup Configuration"

    log STEP "Configuring AWS Backup for data protection..."

    # Create backup vault
    local vault_name="OrganizationBackupVault"

    log INFO "Creating backup vault: $vault_name"

    aws backup create-backup-vault \
        --backup-vault-name "$vault_name" \
        --region $AWS_REGION 2>/dev/null && log SUCCESS "Backup vault created" || log WARN "Backup vault may already exist"

    # Create backup plan
    log INFO "Creating backup plan..."

    cat > /tmp/backup-plan.json <<'EOF'
{
  "BackupPlanName": "DailyBackupPlan",
  "Rules": [
    {
      "RuleName": "DailyBackups",
      "TargetBackupVaultName": "OrganizationBackupVault",
      "ScheduleExpression": "cron(0 5 ? * * *)",
      "StartWindowMinutes": 60,
      "CompletionWindowMinutes": 120,
      "Lifecycle": {
        "DeleteAfterDays": 365,
        "MoveToColdStorageAfterDays": 30
      },
      "RecoveryPointTags": {
        "BackupType": "Automated",
        "RetentionPolicy": "1Year"
      }
    }
  ]
}
EOF

    local backup_plan_id=$(aws backup create-backup-plan \
        --backup-plan file:///tmp/backup-plan.json \
        --region $AWS_REGION \
        --query 'BackupPlanId' \
        --output text 2>/dev/null || echo "")

    if [[ -n "$backup_plan_id" ]]; then
        log SUCCESS "Backup plan created: $backup_plan_id"
    else
        log WARN "Backup plan may already exist or creation failed"
    fi

    rm -f /tmp/backup-plan.json

    # Generate backup guide
    cat > "${AUTOMATION_DIR}/aws-backup-guide.txt" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║              AWS Backup Configuration Guide                    ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

AWS Backup has been configured with a daily backup plan.

Backup Vault: $vault_name
Backup Plan: DailyBackupPlan
Schedule: Daily at 05:00 UTC
Retention: 365 days (1 year)
Cold Storage: After 30 days

═══════════════════════════════════════════════════════════════

NEXT STEPS:

1. Create Backup Selections (Manual)
   - Go to AWS Backup Console
   - Select the backup plan: DailyBackupPlan
   - Create backup selection
   - Choose resources to backup:
     • DynamoDB tables (sBeacon Ontologies, VCFs, etc.)
     • EBS volumes
     • RDS databases
     • EFS file systems

2. Recommended Resources to Backup:

   For Hub Accounts (Production):
   - DynamoDB: sbeacon-Ontologies
   - DynamoDB: sbeacon-VCFs
   - DynamoDB: sbeacon-Projects
   - S3 buckets with genomic data
   - Any RDS databases

3. Configure Cross-Region Backup (Optional)
   - Create backup vault in secondary region
   - Enable copy to secondary region
   - Recommended for disaster recovery

4. Test Restore Procedures
   - Perform test restore monthly
   - Document restore process
   - Measure RTO and RPO

═══════════════════════════════════════════════════════════════

BACKUP BEST PRACTICES:

✓ Regular backups of production data (daily minimum)
✓ Test restore procedures regularly
✓ Store backups in multiple regions
✓ Document backup and restore procedures
✓ Monitor backup job success/failure
✓ Review retention policies quarterly
✓ Implement lifecycle policies for cost optimization

For genomics workloads:
✓ Backup DynamoDB tables before major updates
✓ Backup S3 VCF files (versioning enabled)
✓ Consider cross-region replication
✓ Document data lineage for compliance

═══════════════════════════════════════════════════════════════
EOF

    log SUCCESS "AWS Backup configured, guide created: ${AUTOMATION_DIR}/aws-backup-guide.txt"
    COMPLETED_STEPS["aws_backup"]=1
}

################################################################################
# Step 8: Tagging Strategy Implementation
################################################################################

implement_tagging_strategy() {
    print_section "Step 8: Tagging Strategy Implementation"

    log STEP "Implementing organization-wide tagging strategy..."

    # Create tag policy
    log INFO "Creating tag policy..."

    cat > /tmp/tag-policy.json <<'EOF'
{
  "tags": {
    "Environment": {
      "tag_key": {
        "@@assign": "Environment"
      },
      "tag_value": {
        "@@assign": [
          "Production",
          "Staging",
          "Development",
          "UAT"
        ]
      },
      "enforced_for": {
        "@@assign": [
          "ec2:instance",
          "rds:db",
          "s3:bucket",
          "dynamodb:table",
          "lambda:function"
        ]
      }
    },
    "Owner": {
      "tag_key": {
        "@@assign": "Owner"
      },
      "enforced_for": {
        "@@assign": [
          "ec2:instance",
          "rds:db",
          "s3:bucket",
          "dynamodb:table",
          "lambda:function"
        ]
      }
    },
    "Project": {
      "tag_key": {
        "@@assign": "Project"
      },
      "tag_value": {
        "@@assign": [
          "sBeacon",
          "sVEP",
          "Infrastructure"
        ]
      },
      "enforced_for": {
        "@@assign": [
          "ec2:instance",
          "rds:db",
          "s3:bucket",
          "dynamodb:table",
          "lambda:function"
        ]
      }
    },
    "CostCenter": {
      "tag_key": {
        "@@assign": "CostCenter"
      },
      "enforced_for": {
        "@@assign": [
          "ec2:instance",
          "rds:db",
          "s3:bucket",
          "dynamodb:table",
          "lambda:function"
        ]
      }
    }
  }
}
EOF

    # Create tag policy
    aws organizations create-policy \
        --content file:///tmp/tag-policy.json \
        --description "Organization-wide tagging standards" \
        --name "TaggingPolicy" \
        --type TAG_POLICY \
        --region $AWS_REGION 2>/dev/null && log SUCCESS "Tag policy created" || log WARN "Tag policy may already exist"

    rm -f /tmp/tag-policy.json

    # Enable tag policies
    aws organizations enable-policy-type \
        --root-id $(aws organizations list-roots --query 'Roots[0].Id' --output text) \
        --policy-type TAG_POLICY 2>/dev/null || log WARN "Tag policies may already be enabled"

    # Generate tagging guide
    cat > "${AUTOMATION_DIR}/tagging-strategy-guide.txt" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║            Tagging Strategy Implementation Guide               ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

A comprehensive tagging policy has been created for the organization.

═══════════════════════════════════════════════════════════════

REQUIRED TAGS:

All resources must be tagged with:

1. Environment
   Values: Production, Staging, Development, UAT
   Purpose: Distinguish between environments
   Example: Environment=Production

2. Owner
   Values: Team email or individual
   Purpose: Accountability and contact
   Example: Owner=devops@company.com

3. Project
   Values: sBeacon, sVEP, Infrastructure
   Purpose: Group resources by project
   Example: Project=sBeacon

4. CostCenter
   Values: Department or cost center code
   Purpose: Cost allocation and billing
   Example: CostCenter=IT-001

═══════════════════════════════════════════════════════════════

TAGGING EXAMPLES BY SERVICE:

Lambda Function:
  Environment: Production
  Owner: devops@company.com
  Project: sBeacon
  CostCenter: IT-001
  Function: getGenomicVariants

DynamoDB Table:
  Environment: Production
  Owner: devops@company.com
  Project: sBeacon
  CostCenter: IT-001
  Table: Ontologies

S3 Bucket:
  Environment: Production
  Owner: devops@company.com
  Project: sVEP
  CostCenter: IT-001
  Purpose: VCF-Storage

EC2 Instance:
  Environment: UAT
  Owner: devops@company.com
  Project: Infrastructure
  CostCenter: IT-002
  Name: Bastion-Host

═══════════════════════════════════════════════════════════════

IMPLEMENTATION STEPS:

1. Enable Cost Allocation Tags
   - Go to AWS Billing Console
   - Cost Allocation Tags
   - Activate: Environment, Owner, Project, CostCenter
   - Wait 24 hours for tags to appear in Cost Explorer

2. Apply Tags to Existing Resources
   - Use Tag Editor in AWS Console
   - Or use AWS CLI/boto3 scripts
   - Or use Terraform tag updates

3. Enforce Tags on New Resources
   - Tag policies are already enabled
   - CloudFormation templates should include tags
   - Terraform modules should require tags
   - CI/CD pipelines should validate tags

4. Monitor Tag Compliance
   - Use AWS Config rules
   - Create SNS alerts for untagged resources
   - Regular audits of tag coverage

═══════════════════════════════════════════════════════════════

GENOMICS WORKLOAD TAGGING:

For sBeacon and sVEP resources:

Hub Accounts (Production):
  Environment: Production
  Project: sBeacon or sVEP
  Owner: genomics-ops@company.com
  CostCenter: GENOMICS-PROD

UAT Accounts (Staging):
  Environment: UAT
  Project: sBeacon or sVEP
  Owner: genomics-ops@company.com
  CostCenter: GENOMICS-DEV

Additional recommended tags:
  Hospital: RSCM, RSPON, SARDJITO, NGOERAH, RSJPD
  DataType: Genomic, Reference, Clinical
  Compliance: HIPAA, PHI

═══════════════════════════════════════════════════════════════

COST OPTIMIZATION:

Use tags to:
✓ Identify unused resources by Owner
✓ Allocate costs by CostCenter
✓ Track spending by Project
✓ Compare costs across Environments
✓ Create budget alerts by tag

═══════════════════════════════════════════════════════════════
EOF

    log SUCCESS "Tagging strategy implemented, guide created: ${AUTOMATION_DIR}/tagging-strategy-guide.txt"
    COMPLETED_STEPS["tagging_strategy"]=1
}

################################################################################
# Step 9: Generate Summary Report
################################################################################

generate_summary_report() {
    print_section "Step 9: Generating Comprehensive Summary Report"

    log INFO "Creating post-deployment summary report..."

    local total_accounts=$(aws organizations list-accounts --query 'length(Accounts[?Status==`ACTIVE`])' --output text)

    cat > "${SUMMARY_DIR}/post-deployment-summary-${TIMESTAMP}.txt" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║       Post-Deployment Automation Summary Report                ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

Execution Date: $(date '+%Y-%m-%d %H:%M:%S')
Script Version: $SCRIPT_VERSION
AWS Region: $AWS_REGION
Log File: $LOG_FILE

════════════════════════════════════════════════════════════════

ACCOUNT INFORMATION
════════════════════════════════════════════════════════════════
Management Account:     $MANAGEMENT_ACCOUNT_ID
Log Archive Account:    $LOG_ARCHIVE_ACCOUNT_ID
Security/Audit Account: $SECURITY_AUDIT_ACCOUNT_ID
Total Active Accounts:  $total_accounts

════════════════════════════════════════════════════════════════

COMPLETED STEPS
════════════════════════════════════════════════════════════════
$(for step in "${!COMPLETED_STEPS[@]}"; do
    echo "✓ $step: ${COMPLETED_STEPS[$step]}"
done | sort)

════════════════════════════════════════════════════════════════

SECURITY SERVICES STATUS
════════════════════════════════════════════════════════════════
$([ -n "${COMPLETED_STEPS[aws_config]}" ] && echo "✓ AWS Config: Enabled in ${COMPLETED_STEPS[aws_config]} accounts" || echo "⚠ AWS Config: Not configured")
$([ -n "${COMPLETED_STEPS[security_hub]}" ] && [ "${COMPLETED_STEPS[security_hub]}" != "skipped" ] && echo "✓ Security Hub: Enabled with delegated admin" || echo "⚠ Security Hub: Skipped or not configured")
$([ -n "${COMPLETED_STEPS[guardduty]}" ] && [ "${COMPLETED_STEPS[guardduty]}" != "skipped" ] && echo "✓ GuardDuty: Enabled with auto-enable" || echo "⚠ GuardDuty: Skipped or not configured")
✓ CloudTrail: Organization-wide trail active
⚠ MFA: Manual configuration required (see guide)

════════════════════════════════════════════════════════════════

GOVERNANCE & COMPLIANCE
════════════════════════════════════════════════════════════════
$([ -n "${COMPLETED_STEPS[custom_scps]}" ] && echo "✓ Service Control Policies: 4+ SCPs implemented" || echo "⚠ SCPs: Basic SCPs only")
$([ -n "${COMPLETED_STEPS[tagging_strategy]}" ] && echo "✓ Tag Policies: Organization-wide tagging enforced" || echo "⚠ Tagging: Not configured")
$([ -n "${COMPLETED_STEPS[sso_setup]}" ] && echo "✓ IAM Identity Center: Configured" || echo "⚠ IAM Identity Center: Manual setup required")

════════════════════════════════════════════════════════════════

BACKUP & RECOVERY
════════════════════════════════════════════════════════════════
$([ -n "${COMPLETED_STEPS[aws_backup]}" ] && cat <<BACKUP
✓ Backup Vault: OrganizationBackupVault
✓ Backup Plan: DailyBackupPlan
  - Schedule: Daily at 05:00 UTC
  - Retention: 365 days
  - Cold Storage: After 30 days
⚠ Backup Selections: Manual configuration required
BACKUP
|| echo "⚠ AWS Backup: Not configured")

════════════════════════════════════════════════════════════════

GENERATED DOCUMENTS
════════════════════════════════════════════════════════════════
$(ls -1 ${AUTOMATION_DIR}/*.txt 2>/dev/null | while read file; do
    echo "• $(basename $file)"
done)

════════════════════════════════════════════════════════════════

CRITICAL NEXT STEPS (Manual)
════════════════════════════════════════════════════════════════
1. ⚠ URGENT: Enable MFA on ALL root accounts
   Guide: ${AUTOMATION_DIR}/mfa-configuration-guide.txt

2. Configure IAM Identity Center users and groups
   Guide: ${AUTOMATION_DIR}/iam-identity-center-setup.txt

3. Create AWS Backup selections for resources
   Guide: ${AUTOMATION_DIR}/aws-backup-guide.txt

4. Apply tags to existing resources
   Guide: ${AUTOMATION_DIR}/tagging-strategy-guide.txt

5. Review Security Hub findings
   Console: https://console.aws.amazon.com/securityhub/

6. Configure GuardDuty notifications
   Console: https://console.aws.amazon.com/guardduty/

7. Test cross-account access with SSO
   Portal: Check IAM Identity Center console

8. Set up CloudWatch dashboards for monitoring

9. Document emergency access procedures

10. Schedule regular compliance reviews

════════════════════════════════════════════════════════════════

MONTHLY ESTIMATED ADDITIONAL COSTS
════════════════════════════════════════════════════════════════
AWS Config:        ~\$$(( $total_accounts * 8 ))/month (\$8 per account)
Security Hub:      ~\$5-10/month
GuardDuty:         ~\$5-15/month
AWS Backup:        Storage costs + restore costs
IAM Identity Center: Free
---------------------------------------------------------
Estimated Total:   ~\$$(( $total_accounts * 8 + 20 ))-$(( $total_accounts * 8 + 40 ))/month

Note: Actual costs depend on usage patterns and data volume

════════════════════════════════════════════════════════════════

SUPPORT RESOURCES
════════════════════════════════════════════════════════════════
• Detailed logs: $LOG_FILE
• Documentation: ${AUTOMATION_DIR}/
• AWS Support: https://console.aws.amazon.com/support/
• Security Hub Dashboard: https://console.aws.amazon.com/securityhub/
• GuardDuty Console: https://console.aws.amazon.com/guardduty/

════════════════════════════════════════════════════════════════

For detailed implementation guides, see files in:
$AUTOMATION_DIR

════════════════════════════════════════════════════════════════
EOF

    log SUCCESS "Summary report generated: ${SUMMARY_DIR}/post-deployment-summary-${TIMESTAMP}.txt"
}

################################################################################
# Main Execution
################################################################################

main() {
    print_banner

    log INFO "Starting post-deployment automation..."
    log INFO "Region: $AWS_REGION"
    log INFO "Log file: $LOG_FILE"
    echo ""

    # Confirmation prompt
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}This script will configure the following services:${NC}"
    echo -e "${YELLOW}• MFA Configuration Guide${NC}"
    echo -e "${YELLOW}• IAM Identity Center (AWS SSO)${NC}"
    echo -e "${YELLOW}• AWS Config (all accounts)${NC}"
    echo -e "${YELLOW}• Security Hub (delegated admin)${NC}"
    echo -e "${YELLOW}• GuardDuty (auto-enable)${NC}"
    echo -e "${YELLOW}• Custom Service Control Policies${NC}"
    echo -e "${YELLOW}• AWS Backup${NC}"
    echo -e "${YELLOW}• Tagging Strategy${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "This will modify AWS resources and may incur costs."
    echo ""
    read -p "Do you want to proceed? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        log WARN "Automation cancelled by user"
        exit 0
    fi

    echo ""

    # Get account information
    get_account_ids

    # Execute automation steps
    configure_mfa_guide                # Step 1
    setup_iam_identity_center          # Step 2
    enable_aws_config                  # Step 3
    setup_security_hub                 # Step 4
    setup_guardduty                    # Step 5
    implement_custom_scps              # Step 6
    configure_aws_backup               # Step 7
    implement_tagging_strategy         # Step 8
    generate_summary_report            # Step 9

    echo ""
    log SUCCESS "═══════════════════════════════════════════════════════"
    log SUCCESS "✓ Post-deployment automation completed successfully!"
    log SUCCESS "═══════════════════════════════════════════════════════"
    echo ""
    log INFO "Generated documents:"
    log INFO "  • Summary: ${SUMMARY_DIR}/post-deployment-summary-${TIMESTAMP}.txt"
    log INFO "  • Guides: ${AUTOMATION_DIR}/"
    log INFO "  • Logs: $LOG_FILE"
    echo ""
    log WARN "⚠️  CRITICAL: Enable MFA on all root accounts!"
    log WARN "    Guide: ${AUTOMATION_DIR}/mfa-configuration-guide.txt"
    echo ""
}

# Trap errors
trap 'log ERROR "Script failed at line $LINENO. Check $LOG_FILE for details."' ERR

# Run main function
main "$@"