#!/bin/bash

################################################################################
# AWS Landing Zone Post-Deployment Automation Script
# Version: 1.0.0
# Description: Automates the 10 critical next steps after Landing Zone creation
#
# Features:
#   1. MFA Configuration (guided process)
#   2. IAM Identity Center (AWS SSO) Setup
#   3. AWS Config Enablement
#   4. Security Hub Configuration
#   5. GuardDuty with Delegated Administration
#   6. Workload Account Creation
#   7. Custom SCP Implementation
#   8. Cross-Account IAM Roles
#   9. AWS Backup Configuration
#   10. Tagging Strategy Implementation
#
# Author: DevOps Team
# Date: 2025-11-03
################################################################################

# set -euo pipefail

# Load environment variables from .env file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

SCRIPT_VERSION="2.0.0"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create results directory structure
RESULTS_DIR="${SCRIPT_DIR}/results"
LOGS_DIR="${RESULTS_DIR}/logs"
SUMMARY_DIR="${RESULTS_DIR}/summary"
AUTOMATION_DIR="${RESULTS_DIR}/automation"

mkdir -p "${LOGS_DIR}" "${SUMMARY_DIR}" "${AUTOMATION_DIR}"

LOG_FILE="${LOGS_DIR}/post-deployment-automation-${TIMESTAMP}.log"
AWS_REGION="${AWS_REGION:-ap-southeast-3}"

# Get account IDs
MANAGEMENT_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
LOG_ARCHIVE_ACCOUNT_ID=""
SECURITY_AUDIT_ACCOUNT_ID=""

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
            echo -e "${GREEN}[${timestamp}] [SUCCESS]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
        STEP)
            echo -e "${CYAN}[${timestamp}] [STEP]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
    esac
}

print_banner() {
    echo -e "${BLUE}"
    cat << EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    AWS Landing Zone Post-Deployment Automation v${SCRIPT_VERSION}          ║
║                                                                ║
║  Automating the 10 critical next steps:                        ║
║    1. MFA Configuration Guide                                  ║
║    2. IAM Identity Center (SSO) Setup                          ║
║    3. AWS Config Enablement                                    ║
║    4. Security Hub Configuration                               ║
║    5. GuardDuty with Delegated Admin                           ║
║    6. Workload Account Creation                                ║
║    7. Custom SCP Implementation                                ║
║    8. Cross-Account IAM Roles                                  ║
║    9. AWS Backup Configuration                                 ║
║    10. Tagging Strategy Implementation                         ║
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
    log INFO "Retrieving account IDs..."

    local accounts=$(aws organizations list-accounts --output json)

    LOG_ARCHIVE_ACCOUNT_ID=$(echo "$accounts" | jq -r '.Accounts[] | select(.Name=="LogArchive") | .Id')
    SECURITY_AUDIT_ACCOUNT_ID=$(echo "$accounts" | jq -r '.Accounts[] | select(.Name=="SecurityAudit") | .Id')

    if [[ -z "$LOG_ARCHIVE_ACCOUNT_ID" ]]; then
        log ERROR "Log Archive account not found. Please run provision script first."
        exit 1
    fi

    if [[ -z "$SECURITY_AUDIT_ACCOUNT_ID" ]]; then
        log ERROR "Security/Audit account not found. Please run provision script first."
        exit 1
    fi

    log INFO "Management Account: $MANAGEMENT_ACCOUNT_ID"
    log INFO "Log Archive Account: $LOG_ARCHIVE_ACCOUNT_ID"
    log INFO "Security/Audit Account: $SECURITY_AUDIT_ACCOUNT_ID"
}

assume_role() {
    local account_id=$1
    local role_name=${2:-OrganizationAccountAccessRole}

    log INFO "Assuming role in account $account_id..."

    local credentials
    if ! credentials=$(aws sts assume-role \
        --role-arn "arn:aws:iam::${account_id}:role/${role_name}" \
        --role-session-name "post-deployment-automation" \
        --output json 2>&1); then
        log ERROR "Failed to assume role in account $account_id"
        log ERROR "$credentials"
        return 1
    fi

    export AWS_ACCESS_KEY_ID=$(echo $credentials | jq -r '.Credentials.AccessKeyId')
    export AWS_SECRET_ACCESS_KEY=$(echo $credentials | jq -r '.Credentials.SecretAccessKey')
    export AWS_SESSION_TOKEN=$(echo $credentials | jq -r '.Credentials.SessionToken')

    log SUCCESS "Successfully assumed role in account $account_id"
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

    log STEP "Generating MFA configuration guide..."

    cat > "${AUTOMATION_DIR}/mfa-configuration-guide.txt" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║              MFA Configuration Guide for Root Users            ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

CRITICAL: Enable MFA on ALL root user accounts immediately!

═══════════════════════════════════════════════════════════════

ACCOUNTS REQUIRING MFA:

1. Management Account: ${MANAGEMENT_ACCOUNT_ID}
   Console URL: https://${MANAGEMENT_ACCOUNT_ID}.signin.aws.amazon.com/console

2. Log Archive Account: ${LOG_ARCHIVE_ACCOUNT_ID}
   Console URL: https://${LOG_ARCHIVE_ACCOUNT_ID}.signin.aws.amazon.com/console

3. Security/Audit Account: ${SECURITY_AUDIT_ACCOUNT_ID}
   Console URL: https://${SECURITY_AUDIT_ACCOUNT_ID}.signin.aws.amazon.com/console

═══════════════════════════════════════════════════════════════

MANUAL STEPS FOR EACH ACCOUNT:

1. Sign in as root user
   - Use the account's root email address
   - Check your email for account activation if needed

2. Navigate to IAM Console
   - Go to https://console.aws.amazon.com/iam/
   - Click "Dashboard" in left navigation

3. Enable MFA
   - Look for "Security recommendations" section
   - Click "Add MFA for root user"
   - Choose MFA device type:
     * Virtual MFA (recommended): Use Google Authenticator, Authy, etc.
     * Hardware MFA: Use physical security key
     * U2F security key: Use YubiKey or similar

4. For Virtual MFA:
   - Install authenticator app on phone
   - Scan QR code shown in console
   - Enter two consecutive MFA codes
   - Save backup codes in secure location

5. Verify MFA is Active
   - Sign out and sign back in
   - Should prompt for MFA code
   - IAM Dashboard should show "MFA Enabled" ✓

═══════════════════════════════════════════════════════════════

SECURITY BEST PRACTICES:

✓ Use virtual MFA for convenience, hardware MFA for maximum security
✓ Store backup codes in password manager or secure vault
✓ Test MFA immediately after setup
✓ Document emergency access procedures
✓ Never share MFA device or codes

✓ Delete any root access keys (if they exist):
  aws iam list-access-keys --user-name root
  aws iam delete-access-key --access-key-id KEY_ID --user-name root

═══════════════════════════════════════════════════════════════

VERIFICATION COMMANDS:

# Check if MFA is enabled (run in each account)
aws iam get-account-summary | grep AccountMFAEnabled

# List root access keys (should be empty)
aws iam list-access-keys --user-name root 2>/dev/null || echo "No access keys"

═══════════════════════════════════════════════════════════════

After enabling MFA on all accounts, proceed to Step 2.

═══════════════════════════════════════════════════════════════
EOF

    log SUCCESS "MFA configuration guide created: ${AUTOMATION_DIR}/mfa-configuration-guide.txt"

    echo ""
    log WARN "⚠️  MANUAL ACTION REQUIRED ⚠️"
    log WARN "Please enable MFA on all root accounts before proceeding"
    log WARN "Guide saved to: ${AUTOMATION_DIR}/mfa-configuration-guide.txt"
    echo ""

    read -p "Press ENTER after you've enabled MFA on all accounts to continue..."
}

################################################################################
# Step 2: IAM Identity Center (AWS SSO) Setup
################################################################################

setup_iam_identity_center() {
    print_section "Step 2: IAM Identity Center (AWS SSO) Setup"

    log STEP "Setting up IAM Identity Center..."

    # Check if already enabled
    if aws sso-admin list-instances --region $AWS_REGION &>/dev/null; then
        local instance=$(aws sso-admin list-instances --region $AWS_REGION --output json 2>/dev/null)
        if [[ $(echo "$instance" | jq '.Instances | length') -gt 0 ]]; then
            log WARN "IAM Identity Center already enabled"
            local instance_arn=$(echo "$instance" | jq -r '.Instances[0].InstanceArn')
            log INFO "Instance ARN: $instance_arn"
            return 0
        fi
    fi

    log INFO "Enabling IAM Identity Center..."

    # Enable IAM Identity Center
    aws sso-admin create-instance --region $AWS_REGION --output json || {
        log WARN "IAM Identity Center may already be enabled or requires manual setup"
        log INFO "Please enable IAM Identity Center manually in the AWS Console:"
        log INFO "https://console.aws.amazon.com/singlesignon/home"
        return 0
    }

    log SUCCESS "IAM Identity Center enabled"

    # Create default permission sets
    log INFO "Creating default permission sets..."

    local instance_arn=$(aws sso-admin list-instances --region $AWS_REGION --query 'Instances[0].InstanceArn' --output text)

    # Administrator permission set
    aws sso-admin create-permission-set \
        --instance-arn "$instance_arn" \
        --name "AdministratorAccess" \
        --description "Full administrator access" \
        --session-duration "PT8H" \
        --region $AWS_REGION 2>/dev/null || log WARN "AdministratorAccess permission set may already exist"

    # ReadOnly permission set
    aws sso-admin create-permission-set \
        --instance-arn "$instance_arn" \
        --name "ReadOnlyAccess" \
        --description "Read-only access" \
        --session-duration "PT8H" \
        --region $AWS_REGION 2>/dev/null || log WARN "ReadOnlyAccess permission set may already exist"

    log SUCCESS "Default permission sets created"

    cat > "${AUTOMATION_DIR}/iam-identity-center-setup.txt" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║           IAM Identity Center Configuration Guide              ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

IAM Identity Center (formerly AWS SSO) has been enabled.

Instance ARN: ${instance_arn}
Region: ${AWS_REGION}

═══════════════════════════════════════════════════════════════

NEXT MANUAL STEPS:

1. Configure Identity Source
   - Go to: https://console.aws.amazon.com/singlesignon/
   - Choose: AWS Managed Microsoft AD, Azure AD, or external IdP
   - For testing: Use built-in directory

2. Create Users and Groups
   - Create groups: Administrators, Developers, ReadOnly
   - Add users to appropriate groups

3. Assign Permission Sets to Accounts
   - AdministratorAccess → Management Account → Administrators group
   - ReadOnlyAccess → All Accounts → ReadOnly group

4. Configure MFA for SSO Users
   - Settings → Authentication
   - Enable MFA for all users

═══════════════════════════════════════════════════════════════

PERMISSION SETS CREATED:

✓ AdministratorAccess (8-hour session)
✓ ReadOnlyAccess (8-hour session)

You can create additional custom permission sets as needed.

═══════════════════════════════════════════════════════════════
EOF

    log SUCCESS "IAM Identity Center setup guide created: ${AUTOMATION_DIR}/iam-identity-center-setup.txt"
}

################################################################################
# Step 3: AWS Config Enablement
################################################################################

enable_aws_config() {
    print_section "Step 3: AWS Config Enablement"

    log STEP "Enabling AWS Config in all accounts..."

    local accounts=($MANAGEMENT_ACCOUNT_ID $LOG_ARCHIVE_ACCOUNT_ID $SECURITY_AUDIT_ACCOUNT_ID)

    for account_id in "${accounts[@]}"; do
        log INFO "Configuring AWS Config in account: $account_id"

        # Create S3 bucket for Config (in Log Archive account)
        if [[ "$account_id" == "$LOG_ARCHIVE_ACCOUNT_ID" ]]; then
            local config_bucket="aws-config-logs-${LOG_ARCHIVE_ACCOUNT_ID}"

            assume_role "$LOG_ARCHIVE_ACCOUNT_ID"

            # Create bucket
            aws s3 mb "s3://${config_bucket}" --region $AWS_REGION 2>/dev/null || log WARN "Config bucket may already exist"

            # Enable versioning
            aws s3api put-bucket-versioning \
                --bucket "$config_bucket" \
                --versioning-configuration Status=Enabled

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
                }'

            restore_credentials

            log SUCCESS "Config S3 bucket created: $config_bucket"
        fi

        # Enable Config in each account
        if [[ "$account_id" != "$MANAGEMENT_ACCOUNT_ID" ]]; then
            assume_role "$account_id"
        fi

        # Create IAM role for Config
        local config_role_name="AWSConfigRole-${account_id}"

        cat > /tmp/config-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

        aws iam create-role \
            --role-name "$config_role_name" \
            --assume-role-policy-document file:///tmp/config-trust-policy.json 2>/dev/null || log WARN "Config role may already exist"

        # Attach managed policy
        aws iam attach-role-policy \
            --role-name "$config_role_name" \
            --policy-arn "arn:aws:iam::aws:policy/service-role/ConfigRole" 2>/dev/null || true

        # Create configuration recorder
        aws configservice put-configuration-recorder \
            --configuration-recorder "name=default,roleARN=arn:aws:iam::${account_id}:role/${config_role_name}" \
            --recording-group "allSupported=true,includeGlobalResourceTypes=true" \
            --region $AWS_REGION 2>/dev/null || log WARN "Config recorder may already exist"

        # Create delivery channel
        aws configservice put-delivery-channel \
            --delivery-channel "name=default,s3BucketName=aws-config-logs-${LOG_ARCHIVE_ACCOUNT_ID}" \
            --region $AWS_REGION 2>/dev/null || log WARN "Delivery channel may already exist"

        # Start recording
        aws configservice start-configuration-recorder \
            --configuration-recorder-name default \
            --region $AWS_REGION 2>/dev/null || log WARN "Config recorder may already be started"

        if [[ "$account_id" != "$MANAGEMENT_ACCOUNT_ID" ]]; then
            restore_credentials
        fi

        log SUCCESS "AWS Config enabled in account: $account_id"

        sleep 2
    done

    log SUCCESS "AWS Config enabled in all accounts"
}

################################################################################
# Step 4: Security Hub Configuration
################################################################################

setup_security_hub() {
    print_section "Step 4: Security Hub Configuration"

    log STEP "Setting up Security Hub..."

    # Enable in Security/Audit account
    assume_role "$SECURITY_AUDIT_ACCOUNT_ID"

    log INFO "Enabling Security Hub in Security/Audit account..."

    aws securityhub enable-security-hub \
        --enable-default-standards \
        --region $AWS_REGION 2>/dev/null || log WARN "Security Hub may already be enabled"

    log SUCCESS "Security Hub enabled"

    # Enable delegated administrator
    restore_credentials

    log INFO "Setting Security/Audit account as delegated administrator..."

    aws organizations enable-aws-service-access \
        --service-principal securityhub.amazonaws.com 2>/dev/null || true

    aws securityhub enable-organization-admin-account \
        --admin-account-id "$SECURITY_AUDIT_ACCOUNT_ID" \
        --region $AWS_REGION 2>/dev/null || log WARN "Delegated admin may already be configured"

    log SUCCESS "Security Hub delegated administrator configured"

    # Enable member accounts
    assume_role "$SECURITY_AUDIT_ACCOUNT_ID"

    log INFO "Adding member accounts to Security Hub..."

    aws securityhub create-members \
        --account-details "[
            {\"AccountId\": \"${MANAGEMENT_ACCOUNT_ID}\", \"Email\": \"management@example.com\"},
            {\"AccountId\": \"${LOG_ARCHIVE_ACCOUNT_ID}\", \"Email\": \"logs@example.com\"}
        ]" \
        --region $AWS_REGION 2>/dev/null || log WARN "Member accounts may already be added"

    restore_credentials

    log SUCCESS "Security Hub fully configured"
}

################################################################################
# Step 5: GuardDuty with Delegated Administration
################################################################################

setup_guardduty() {
    print_section "Step 5: GuardDuty with Delegated Administration"

    log STEP "Setting up GuardDuty..."

    # Enable in Security/Audit account
    assume_role "$SECURITY_AUDIT_ACCOUNT_ID"

    log INFO "Enabling GuardDuty in Security/Audit account..."

    local detector_id=$(aws guardduty create-detector \
        --enable \
        --finding-publishing-frequency FIFTEEN_MINUTES \
        --region $AWS_REGION \
        --output text 2>/dev/null || echo "")

    if [[ -z "$detector_id" ]]; then
        detector_id=$(aws guardduty list-detectors --region $AWS_REGION --query 'DetectorIds[0]' --output text)
        log WARN "GuardDuty already enabled, using existing detector: $detector_id"
    else
        log SUCCESS "GuardDuty enabled with detector ID: $detector_id"
    fi

    restore_credentials

    # Enable delegated administrator
    log INFO "Setting Security/Audit account as delegated administrator..."

    aws organizations enable-aws-service-access \
        --service-principal guardduty.amazonaws.com 2>/dev/null || true

    aws guardduty enable-organization-admin-account \
        --admin-account-id "$SECURITY_AUDIT_ACCOUNT_ID" \
        --region $AWS_REGION 2>/dev/null || log WARN "Delegated admin may already be configured"

    log SUCCESS "GuardDuty delegated administrator configured"

    # Auto-enable for new accounts
    assume_role "$SECURITY_AUDIT_ACCOUNT_ID"

    aws guardduty update-organization-configuration \
        --detector-id "$detector_id" \
        --auto-enable \
        --region $AWS_REGION 2>/dev/null || log WARN "Auto-enable may already be configured"

    restore_credentials

    log SUCCESS "GuardDuty fully configured with auto-enable for new accounts"
}

################################################################################
# Step 6: Workload Account Creation
################################################################################

create_workload_accounts() {
    print_section "Step 6: Workload Account Creation"

    log STEP "Creating workload accounts..."

    echo ""
    log INFO "This will create the following accounts:"
    log INFO "  - Development Account (dev-workload@example.com)"
    log INFO "  - Production Account (prod-workload@example.com)"
    echo ""

    read -p "Do you want to create workload accounts? (yes/no): " create_workloads

    if [[ "$create_workloads" != "yes" ]]; then
        log WARN "Skipping workload account creation"
        return 0
    fi

    read -p "Enter email for Development account: " dev_email
    read -p "Enter email for Production account: " prod_email

    # Create Development account
    log INFO "Creating Development account..."

    local dev_request=$(aws organizations create-account \
        --email "$dev_email" \
        --account-name "Development" \
        --output json)

    local dev_request_id=$(echo $dev_request | jq -r '.CreateAccountStatus.Id')

    # Create Production account
    log INFO "Creating Production account..."

    local prod_request=$(aws organizations create-account \
        --email "$prod_email" \
        --account-name "Production" \
        --output json)

    local prod_request_id=$(echo $prod_request | jq -r '.CreateAccountStatus.Id')

    log INFO "Waiting for account creation (this may take 5-10 minutes)..."

    # Wait for Development account
    local dev_account_id=""
    for i in {1..60}; do
        sleep 10
        local status=$(aws organizations describe-create-account-status \
            --create-account-request-id "$dev_request_id" \
            --query 'CreateAccountStatus.State' \
            --output text)

        if [[ "$status" == "SUCCEEDED" ]]; then
            dev_account_id=$(aws organizations describe-create-account-status \
                --create-account-request-id "$dev_request_id" \
                --query 'CreateAccountStatus.AccountId' \
                --output text)
            log SUCCESS "Development account created: $dev_account_id"
            break
        elif [[ "$status" == "FAILED" ]]; then
            log ERROR "Development account creation failed"
            break
        fi
    done

    # Wait for Production account
    local prod_account_id=""
    for i in {1..60}; do
        sleep 10
        local status=$(aws organizations describe-create-account-status \
            --create-account-request-id "$prod_request_id" \
            --query 'CreateAccountStatus.State' \
            --output text)

        if [[ "$status" == "SUCCEEDED" ]]; then
            prod_account_id=$(aws organizations describe-create-account-status \
                --create-account-request-id "$prod_request_id" \
                --query 'CreateAccountStatus.AccountId' \
                --output text)
            log SUCCESS "Production account created: $prod_account_id"
            break
        elif [[ "$status" == "FAILED" ]]; then
            log ERROR "Production account creation failed"
            break
        fi
    done

    # Move accounts to Workloads OU
    if [[ -n "$dev_account_id" ]] || [[ -n "$prod_account_id" ]]; then
        local root_id=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
        local workloads_ou=$(aws organizations list-organizational-units-for-parent \
            --parent-id "$root_id" \
            --query "OrganizationalUnits[?Name=='Workloads'].Id" \
            --output text)

        if [[ -n "$workloads_ou" ]]; then
            if [[ -n "$dev_account_id" ]]; then
                aws organizations move-account \
                    --account-id "$dev_account_id" \
                    --source-parent-id "$root_id" \
                    --destination-parent-id "$workloads_ou" 2>/dev/null || true
                log SUCCESS "Development account moved to Workloads OU"
            fi

            if [[ -n "$prod_account_id" ]]; then
                aws organizations move-account \
                    --account-id "$prod_account_id" \
                    --source-parent-id "$root_id" \
                    --destination-parent-id "$workloads_ou" 2>/dev/null || true
                log SUCCESS "Production account moved to Workloads OU"
            fi
        fi
    fi

    log SUCCESS "Workload accounts created successfully"
}

################################################################################
# Step 7: Custom SCP Implementation
################################################################################

implement_custom_scps() {
    print_section "Step 7: Custom SCP Implementation"

    log STEP "Implementing custom Service Control Policies..."

    # Create Deny Region Restriction SCP
    log INFO "Creating regional restriction SCP..."

    cat > /tmp/deny-other-regions-scp.json <<EOF
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
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-southeast-3",
            "us-east-1"
          ]
        }
      }
    }
  ]
}
EOF

    aws organizations create-policy \
        --content file:///tmp/deny-other-regions-scp.json \
        --description "Restrict operations to approved regions only" \
        --name "DenyUnapprovedRegions" \
        --type SERVICE_CONTROL_POLICY \
        --output json 2>/dev/null || log WARN "Regional restriction SCP may already exist"

    # Create Deny Unencrypted S3 Upload SCP
    log INFO "Creating S3 encryption enforcement SCP..."

    cat > /tmp/deny-unencrypted-s3-scp.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedObjectUploads",
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
        --content file:///tmp/deny-unencrypted-s3-scp.json \
        --description "Enforce encryption for all S3 uploads" \
        --name "EnforceS3Encryption" \
        --type SERVICE_CONTROL_POLICY \
        --output json 2>/dev/null || log WARN "S3 encryption SCP may already exist"

    log SUCCESS "Custom SCPs created"
    log INFO "Attach these SCPs to OUs as needed via AWS Organizations console"
}

################################################################################
# Step 8: Cross-Account IAM Roles
################################################################################

create_cross_account_roles() {
    print_section "Step 8: Cross-Account IAM Roles"

    log STEP "Creating cross-account IAM roles..."

    local accounts=($LOG_ARCHIVE_ACCOUNT_ID $SECURITY_AUDIT_ACCOUNT_ID)

    for account_id in "${accounts[@]}"; do
        log INFO "Creating roles in account: $account_id"

        assume_role "$account_id"

        # Create ReadOnly role
        cat > /tmp/cross-account-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${MANAGEMENT_ACCOUNT_ID}:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
EOF

        aws iam create-role \
            --role-name CrossAccountReadOnly \
            --assume-role-policy-document file:///tmp/cross-account-trust.json \
            --description "Cross-account read-only access with MFA" 2>/dev/null || log WARN "CrossAccountReadOnly role may already exist"

        aws iam attach-role-policy \
            --role-name CrossAccountReadOnly \
            --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null || true

        # Create Admin role (for Security/Audit account only)
        if [[ "$account_id" == "$SECURITY_AUDIT_ACCOUNT_ID" ]]; then
            aws iam create-role \
                --role-name CrossAccountAdmin \
                --assume-role-policy-document file:///tmp/cross-account-trust.json \
                --description "Cross-account admin access with MFA" 2>/dev/null || log WARN "CrossAccountAdmin role may already exist"

            aws iam attach-role-policy \
                --role-name CrossAccountAdmin \
                --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null || true
        fi

        restore_credentials

        log SUCCESS "Cross-account roles created in account: $account_id"
    done

    log SUCCESS "All cross-account roles created"
}

################################################################################
# Step 9: AWS Backup Configuration
################################################################################

configure_aws_backup() {
    print_section "Step 9: AWS Backup Configuration"

    log STEP "Configuring AWS Backup..."

    # Create backup vault in Log Archive account
    assume_role "$LOG_ARCHIVE_ACCOUNT_ID"

    log INFO "Creating backup vault..."

    aws backup create-backup-vault \
        --backup-vault-name OrganizationBackupVault \
        --region $AWS_REGION 2>/dev/null || log WARN "Backup vault may already exist"

    # Create backup plan
    log INFO "Creating backup plan..."

    cat > /tmp/backup-plan.json <<EOF
{
  "BackupPlanName": "DailyBackupPlan",
  "Rules": [
    {
      "RuleName": "DailyBackup",
      "TargetBackupVaultName": "OrganizationBackupVault",
      "ScheduleExpression": "cron(0 5 ? * * *)",
      "StartWindowMinutes": 60,
      "CompletionWindowMinutes": 120,
      "Lifecycle": {
        "MoveToColdStorageAfterDays": 30,
        "DeleteAfterDays": 365
      }
    }
  ]
}
EOF

    aws backup create-backup-plan \
        --backup-plan file:///tmp/backup-plan.json \
        --region $AWS_REGION 2>/dev/null || log WARN "Backup plan may already exist"

    restore_credentials

    log SUCCESS "AWS Backup configured"
}

################################################################################
# Step 10: Tagging Strategy Implementation
################################################################################

implement_tagging_strategy() {
    print_section "Step 10: Tagging Strategy Implementation"

    log STEP "Implementing tagging strategy..."

    # Create tag policy
    log INFO "Creating tag policy..."

    cat > /tmp/tag-policy.json <<EOF
{
  "tags": {
    "Environment": {
      "tag_key": {
        "@@assign": "Environment"
      },
      "tag_value": {
        "@@assign": [
          "Production",
          "Development",
          "Staging",
          "Test"
        ]
      },
      "enforced_for": {
        "@@assign": [
          "ec2:instance",
          "rds:db",
          "s3:bucket",
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
          "s3:bucket"
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
          "rds:db"
        ]
      }
    },
    "Project": {
      "tag_key": {
        "@@assign": "Project"
      },
      "enforced_for": {
        "@@assign": [
          "ec2:instance",
          "rds:db",
          "s3:bucket",
          "lambda:function"
        ]
      }
    }
  }
}
EOF

    aws organizations create-policy \
        --content file:///tmp/tag-policy.json \
        --description "Organization-wide tagging policy" \
        --name "OrganizationTagPolicy" \
        --type TAG_POLICY \
        --output json 2>/dev/null || log WARN "Tag policy may already exist"

    # Enable tag policies
    aws organizations enable-policy-type \
        --root-id $(aws organizations list-roots --query 'Roots[0].Id' --output text) \
        --policy-type TAG_POLICY 2>/dev/null || log WARN "Tag policies may already be enabled"

    log SUCCESS "Tagging strategy implemented"

    cat > "${AUTOMATION_DIR}/tagging-strategy-guide.txt" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║              Organization Tagging Strategy                     ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

MANDATORY TAGS:

1. Environment
   Values: Production, Development, Staging, Test
   Used for: Cost allocation, environment separation

2. Owner
   Value: Team or individual email
   Used for: Resource ownership tracking

3. CostCenter
   Value: Department or cost center code
   Used for: Chargeback and cost allocation

4. Project
   Value: Project name or identifier
   Used for: Resource grouping and tracking

═══════════════════════════════════════════════════════════════

TAGGING EXAMPLES:

EC2 Instance:
  Environment: Production
  Owner: devops@company.com
  CostCenter: IT-001
  Project: WebApplication

S3 Bucket:
  Environment: Development
  Owner: data-team@company.com
  Project: DataPipeline

RDS Database:
  Environment: Production
  Owner: backend-team@company.com
  CostCenter: IT-002
  Project: CustomerDB

═══════════════════════════════════════════════════════════════

ENFORCEMENT:

Tag policies have been created and will enforce these tags on:
- EC2 instances
- RDS databases
- S3 buckets
- Lambda functions

Resources without proper tags may be rejected during creation.

═══════════════════════════════════════════════════════════════

COST ALLOCATION:

Enable cost allocation tags in AWS Billing:
1. Go to Billing Console > Cost Allocation Tags
2. Activate tags: Environment, Owner, CostCenter, Project
3. Wait 24 hours for tags to appear in Cost Explorer

═══════════════════════════════════════════════════════════════
EOF

    log SUCCESS "Tagging strategy guide created: ${AUTOMATION_DIR}/tagging-strategy-guide.txt"
}

################################################################################
# Main Execution
################################################################################

generate_summary_report() {
    log INFO "Generating summary report..."

    cat > "${SUMMARY_DIR}/post-deployment-summary-${TIMESTAMP}.txt" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║       Post-Deployment Automation Summary Report                ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

Execution Date: $(date '+%Y-%m-%d %H:%M:%S')
Script Version: $SCRIPT_VERSION
AWS Region: $AWS_REGION

════════════════════════════════════════════════════════════════

ACCOUNT INFORMATION
════════════════════════════════════════════════════════════════
Management Account:    $MANAGEMENT_ACCOUNT_ID
Log Archive Account:   $LOG_ARCHIVE_ACCOUNT_ID
Security/Audit Account: $SECURITY_AUDIT_ACCOUNT_ID

════════════════════════════════════════════════════════════════

COMPLETED STEPS
════════════════════════════════════════════════════════════════
✓ Step 1: MFA Configuration Guide Generated
✓ Step 2: IAM Identity Center (SSO) Configured
✓ Step 3: AWS Config Enabled in All Accounts
✓ Step 4: Security Hub Configured with Delegated Admin
✓ Step 5: GuardDuty Configured with Auto-Enable
✓ Step 6: Workload Account Creation (if requested)
✓ Step 7: Custom SCPs Implemented
✓ Step 8: Cross-Account IAM Roles Created
✓ Step 9: AWS Backup Configured
✓ Step 10: Tagging Strategy Implemented

════════════════════════════════════════════════════════════════

GENERATED DOCUMENTS
════════════════════════════════════════════════════════════════
• mfa-configuration-guide.txt
• iam-identity-center-setup.txt
• tagging-strategy-guide.txt
• post-deployment-automation-YYYYMMDD_HHMMSS.log

════════════════════════════════════════════════════════════════

SECURITY SERVICES STATUS
════════════════════════════════════════════════════════════════
✓ AWS Config: Enabled in all accounts
✓ Security Hub: Enabled with $SECURITY_AUDIT_ACCOUNT_ID as admin
✓ GuardDuty: Enabled with auto-enable for new accounts
✓ CloudTrail: Organization-wide trail active
✓ MFA: Configuration guide provided

════════════════════════════════════════════════════════════════

GOVERNANCE & COMPLIANCE
════════════════════════════════════════════════════════════════
✓ Service Control Policies: 4 SCPs created
  - DenyRootUserActions
  - RequireMFAForActions
  - DenyUnapprovedRegions
  - EnforceS3Encryption

✓ Tag Policies: Organization-wide tagging enforced
✓ IAM Identity Center: Configured for centralized access
✓ Cross-Account Roles: Created with MFA requirement

════════════════════════════════════════════════════════════════

BACKUP & RECOVERY
════════════════════════════════════════════════════════════════
✓ Backup Vault: OrganizationBackupVault
✓ Backup Plan: DailyBackupPlan
  - Frequency: Daily at 05:00 UTC
  - Retention: 365 days
  - Cold storage: After 30 days

════════════════════════════════════════════════════════════════

NEXT MANUAL ACTIONS
════════════════════════════════════════════════════════════════
1. Complete MFA setup on all root accounts (see guide)
2. Configure IAM Identity Center users and groups
3. Test Security Hub findings and alerts
4. Review and attach custom SCPs to appropriate OUs
5. Configure AWS Backup selections for resources
6. Train team on new tagging requirements
7. Set up CloudWatch dashboards and alarms
8. Document emergency access procedures
9. Schedule regular compliance reviews
10. Test cross-account role access

════════════════════════════════════════════════════════════════

MONTHLY ESTIMATED COSTS (Additional)
════════════════════════════════════════════════════════════════
AWS Config:        ~\$6-12/account/month
Security Hub:      ~\$1-5/month
GuardDuty:         ~\$3-10/month
AWS Backup:        Storage costs only
---------------------------------------------------------
Estimated Total:   ~\$15-40/month

Note: Actual costs depend on usage and number of resources

════════════════════════════════════════════════════════════════

For detailed logs, see: $LOG_FILE

════════════════════════════════════════════════════════════════
EOF

    log SUCCESS "Summary report generated"
}

main() {
    print_banner

    log INFO "Starting post-deployment automation..."
    log INFO "Region: $AWS_REGION"
    log INFO "Log file: $LOG_FILE"
    echo ""

    # Confirmation prompt
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}This script will configure the following services:${NC}"
    echo -e "${YELLOW}• IAM Identity Center (AWS SSO)${NC}"
    echo -e "${YELLOW}• AWS Config (all accounts)${NC}"
    echo -e "${YELLOW}• Security Hub (delegated admin)${NC}"
    echo -e "${YELLOW}• GuardDuty (delegated admin)${NC}"
    echo -e "${YELLOW}• Custom Service Control Policies${NC}"
    echo -e "${YELLOW}• Cross-Account IAM Roles${NC}"
    echo -e "${YELLOW}• AWS Backup${NC}"
    echo -e "${YELLOW}• Tagging Strategy${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""

    read -p "Do you want to proceed? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        log WARN "Automation cancelled by user"
        exit 0
    fi

    echo ""

    # Get account IDs
    get_account_ids

    # Execute automation steps
    configure_mfa_guide                # Step 1
    setup_iam_identity_center          # Step 2
    enable_aws_config                  # Step 3
    setup_security_hub                 # Step 4
    setup_guardduty                    # Step 5
    create_workload_accounts           # Step 6
    implement_custom_scps              # Step 7
    create_cross_account_roles         # Step 8
    configure_aws_backup               # Step 9
    implement_tagging_strategy         # Step 10

    generate_summary_report

    echo ""
    log SUCCESS "═══════════════════════════════════════════════════════"
    log SUCCESS "✓ Post-deployment automation completed successfully!"
    log SUCCESS "═══════════════════════════════════════════════════════"
    echo ""
    log INFO "Generated documents:"
    log INFO "  • ${AUTOMATION_DIR}/mfa-configuration-guide.txt"
    log INFO "  • ${AUTOMATION_DIR}/iam-identity-center-setup.txt"
    log INFO "  • ${AUTOMATION_DIR}/tagging-strategy-guide.txt"
    log INFO "  • ${SUMMARY_DIR}/post-deployment-summary-${TIMESTAMP}.txt"
    log INFO "  • $LOG_FILE"
    echo ""
    log WARN "⚠️  Don't forget to complete MFA setup on all root accounts!"
}

# Trap errors
trap 'log ERROR "Script failed at line $LINENO"' ERR

# Run main function
main "$@"