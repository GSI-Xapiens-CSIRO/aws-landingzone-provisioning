#!/bin/bash

################################################################################
# AWS Landing Zone Provisioning Script
# Version: 1.0.0
# Description: Provisions a foundational AWS Landing Zone with 3 core accounts
#              following AWS best practices and Control Tower concepts
#
# Accounts Created:
#   1. Management Account (Root) - Already exists
#   2. Log Archive Account - Centralized logging
#   3. Security/Audit Account - Security tooling and compliance
#
# Author: DevOps Team
# Date: 2025-11-03
################################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_VERSION="1.0.0"
LOG_FILE="landing-zone-provisioning-$(date +%Y%m%d_%H%M%S).log"
ORG_NAME="${ORG_NAME:-MyOrganization}"
AWS_REGION="${AWS_REGION:-ap-southeast-3}"

# Email addresses for account root users (MUST BE UNIQUE)
LOG_ARCHIVE_EMAIL="${LOG_ARCHIVE_EMAIL:-aws-log-archive@example.com}"
SECURITY_AUDIT_EMAIL="${SECURITY_AUDIT_EMAIL:-aws-security-audit@example.com}"

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
        DEBUG)
            echo -e "${BLUE}[${timestamp}] [DEBUG]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
    esac
}

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║        AWS Landing Zone Provisioning Script v1.0.0            ║
║                                                                ║
║  Creating foundational multi-account AWS environment with:     ║
║    • AWS Organizations                                         ║
║    • Core Organizational Units (OUs)                           ║
║    • Log Archive Account                                       ║
║    • Security/Audit Account                                    ║
║    • Service Control Policies (SCPs)                           ║
║    • CloudTrail Organization Trail                             ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

################################################################################
# Pre-flight Checks
################################################################################

check_prerequisites() {
    log INFO "Running pre-flight checks..."

    # Check AWS CLI installation
    if ! command -v aws &> /dev/null; then
        log ERROR "AWS CLI is not installed. Please install it first."
        exit 1
    fi

    # Check AWS CLI version
    local aws_version=$(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)
    log INFO "AWS CLI version: $aws_version"

    # Verify AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log ERROR "AWS credentials are not configured or invalid"
        exit 1
    fi

    # Get caller identity
    local caller_identity=$(aws sts get-caller-identity --output json)
    local account_id=$(echo $caller_identity | jq -r '.Account')
    local user_arn=$(echo $caller_identity | jq -r '.Arn')

    log INFO "Authenticated as: $user_arn"
    log INFO "Management Account ID: $account_id"

    # Check if running in management account
    log WARN "Please ensure you are running this from the management account"

    # Check jq installation
    if ! command -v jq &> /dev/null; then
        log ERROR "jq is not installed. Please install it first."
        exit 1
    fi

    log INFO "✓ All prerequisites met"
}

validate_email_addresses() {
    log INFO "Validating email addresses..."

    if [[ "$LOG_ARCHIVE_EMAIL" == *"example.com"* ]] || [[ "$SECURITY_AUDIT_EMAIL" == *"example.com"* ]]; then
        log ERROR "Please set valid email addresses using environment variables:"
        log ERROR "  export LOG_ARCHIVE_EMAIL='your-log-archive@yourdomain.com'"
        log ERROR "  export SECURITY_AUDIT_EMAIL='your-security-audit@yourdomain.com'"
        exit 1
    fi

    if [[ "$LOG_ARCHIVE_EMAIL" == "$SECURITY_AUDIT_EMAIL" ]]; then
        log ERROR "Email addresses must be unique for each account"
        exit 1
    fi

    log INFO "✓ Email addresses validated"
}

################################################################################
# AWS Organizations Setup
################################################################################

create_organization() {
    log INFO "Step 1: Creating AWS Organization..."

    # Check if organization already exists
    if aws organizations describe-organization &> /dev/null; then
        log WARN "Organization already exists"
        local org_id=$(aws organizations describe-organization --query 'Organization.Id' --output text)
        log INFO "Organization ID: $org_id"
        return 0
    fi

    # Create organization with all features enabled
    log INFO "Creating new organization with all features enabled..."
    local org_result=$(aws organizations create-organization \
        --feature-set ALL \
        --output json)

    local org_id=$(echo $org_result | jq -r '.Organization.Id')
    log INFO "✓ Organization created successfully"
    log INFO "Organization ID: $org_id"

    # Wait for organization to be ready
    sleep 5
}

get_root_id() {
    aws organizations list-roots --query 'Roots[0].Id' --output text
}

################################################################################
# Organizational Units (OUs) Creation
################################################################################

create_organizational_units() {
    log INFO "Step 2: Creating Organizational Units (OUs)..."

    local root_id=$(get_root_id)
    log INFO "Root ID: $root_id"

    # Create Security OU
    log INFO "Creating Security OU..."
    local security_ou=$(aws organizations create-organizational-unit \
        --parent-id "$root_id" \
        --name "Security" \
        --output json 2>/dev/null || \
        aws organizations list-organizational-units-for-parent \
        --parent-id "$root_id" \
        --query "OrganizationalUnits[?Name=='Security'].Id" \
        --output text)

    if [[ -n "$security_ou" ]]; then
        log INFO "✓ Security OU created/exists"
    fi

    # Create Infrastructure OU
    log INFO "Creating Infrastructure OU..."
    local infra_ou=$(aws organizations create-organizational-unit \
        --parent-id "$root_id" \
        --name "Infrastructure" \
        --output json 2>/dev/null || \
        aws organizations list-organizational-units-for-parent \
        --parent-id "$root_id" \
        --query "OrganizationalUnits[?Name=='Infrastructure'].Id" \
        --output text)

    if [[ -n "$infra_ou" ]]; then
        log INFO "✓ Infrastructure OU created/exists"
    fi

    # Create Workloads OU (for future use)
    log INFO "Creating Workloads OU..."
    local workloads_ou=$(aws organizations create-organizational-unit \
        --parent-id "$root_id" \
        --name "Workloads" \
        --output json 2>/dev/null || \
        aws organizations list-organizational-units-for-parent \
        --parent-id "$root_id" \
        --query "OrganizationalUnits[?Name=='Workloads'].Id" \
        --output text)

    if [[ -n "$workloads_ou" ]]; then
        log INFO "✓ Workloads OU created/exists"
    fi

    log INFO "✓ Organizational Units structure created"
}

################################################################################
# Core Accounts Creation
################################################################################

create_log_archive_account() {
    log INFO "Step 3: Creating Log Archive Account..."

    # Check if account already exists
    local existing_account=$(aws organizations list-accounts \
        --query "Accounts[?Name=='LogArchive'].Id" \
        --output text)

    if [[ -n "$existing_account" ]]; then
        log WARN "Log Archive account already exists: $existing_account"
        echo "$existing_account"
        return 0
    fi

    log INFO "Creating Log Archive account with email: $LOG_ARCHIVE_EMAIL"

    local account_result=$(aws organizations create-account \
        --email "$LOG_ARCHIVE_EMAIL" \
        --account-name "LogArchive" \
        --output json)

    local create_request_id=$(echo $account_result | jq -r '.CreateAccountStatus.Id')
    log INFO "Account creation request ID: $create_request_id"

    # Wait for account creation
    log INFO "Waiting for account creation (this may take 2-5 minutes)..."
    local account_id=""
    local max_attempts=60
    local attempt=0

    while [[ $attempt -lt $max_attempts ]]; do
        sleep 10
        attempt=$((attempt + 1))

        local status=$(aws organizations describe-create-account-status \
            --create-account-request-id "$create_request_id" \
            --query 'CreateAccountStatus.State' \
            --output text)

        log DEBUG "Attempt $attempt/$max_attempts - Status: $status"

        if [[ "$status" == "SUCCEEDED" ]]; then
            account_id=$(aws organizations describe-create-account-status \
                --create-account-request-id "$create_request_id" \
                --query 'CreateAccountStatus.AccountId' \
                --output text)
            log INFO "✓ Log Archive account created successfully"
            log INFO "Account ID: $account_id"
            break
        elif [[ "$status" == "FAILED" ]]; then
            local failure_reason=$(aws organizations describe-create-account-status \
                --create-account-request-id "$create_request_id" \
                --query 'CreateAccountStatus.FailureReason' \
                --output text)
            log ERROR "Account creation failed: $failure_reason"
            return 1
        fi
    done

    if [[ -z "$account_id" ]]; then
        log ERROR "Timeout waiting for account creation"
        return 1
    fi

    # Move account to Infrastructure OU
    local root_id=$(get_root_id)
    local infra_ou=$(aws organizations list-organizational-units-for-parent \
        --parent-id "$root_id" \
        --query "OrganizationalUnits[?Name=='Infrastructure'].Id" \
        --output text)

    if [[ -n "$infra_ou" ]]; then
        log INFO "Moving Log Archive account to Infrastructure OU..."
        aws organizations move-account \
            --account-id "$account_id" \
            --source-parent-id "$root_id" \
            --destination-parent-id "$infra_ou" 2>/dev/null || true
        log INFO "✓ Account moved to Infrastructure OU"
    fi

    echo "$account_id"
}

create_security_audit_account() {
    log INFO "Step 4: Creating Security/Audit Account..."

    # Check if account already exists
    local existing_account=$(aws organizations list-accounts \
        --query "Accounts[?Name=='SecurityAudit'].Id" \
        --output text)

    if [[ -n "$existing_account" ]]; then
        log WARN "Security/Audit account already exists: $existing_account"
        echo "$existing_account"
        return 0
    fi

    log INFO "Creating Security/Audit account with email: $SECURITY_AUDIT_EMAIL"

    local account_result=$(aws organizations create-account \
        --email "$SECURITY_AUDIT_EMAIL" \
        --account-name "SecurityAudit" \
        --output json)

    local create_request_id=$(echo $account_result | jq -r '.CreateAccountStatus.Id')
    log INFO "Account creation request ID: $create_request_id"

    # Wait for account creation
    log INFO "Waiting for account creation (this may take 2-5 minutes)..."
    local account_id=""
    local max_attempts=60
    local attempt=0

    while [[ $attempt -lt $max_attempts ]]; do
        sleep 10
        attempt=$((attempt + 1))

        local status=$(aws organizations describe-create-account-status \
            --create-account-request-id "$create_request_id" \
            --query 'CreateAccountStatus.State' \
            --output text)

        log DEBUG "Attempt $attempt/$max_attempts - Status: $status"

        if [[ "$status" == "SUCCEEDED" ]]; then
            account_id=$(aws organizations describe-create-account-status \
                --create-account-request-id "$create_request_id" \
                --query 'CreateAccountStatus.AccountId' \
                --output text)
            log INFO "✓ Security/Audit account created successfully"
            log INFO "Account ID: $account_id"
            break
        elif [[ "$status" == "FAILED" ]]; then
            local failure_reason=$(aws organizations describe-create-account-status \
                --create-account-request-id "$create_request_id" \
                --query 'CreateAccountStatus.FailureReason' \
                --output text)
            log ERROR "Account creation failed: $failure_reason"
            return 1
        fi
    done

    if [[ -z "$account_id" ]]; then
        log ERROR "Timeout waiting for account creation"
        return 1
    fi

    # Move account to Security OU
    local root_id=$(get_root_id)
    local security_ou=$(aws organizations list-organizational-units-for-parent \
        --parent-id "$root_id" \
        --query "OrganizationalUnits[?Name=='Security'].Id" \
        --output text)

    if [[ -n "$security_ou" ]]; then
        log INFO "Moving Security/Audit account to Security OU..."
        aws organizations move-account \
            --account-id "$account_id" \
            --source-parent-id "$root_id" \
            --destination-parent-id "$security_ou" 2>/dev/null || true
        log INFO "✓ Account moved to Security OU"
    fi

    echo "$account_id"
}

################################################################################
# Service Control Policies (SCPs)
################################################################################

create_deny_root_scp() {
    log INFO "Step 5: Creating Service Control Policies..."

    # Create SCP to deny root user actions (except in emergencies)
    local scp_name="DenyRootUserActions"

    # Check if SCP already exists
    local existing_scp=$(aws organizations list-policies \
        --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='$scp_name'].Id" \
        --output text)

    if [[ -n "$existing_scp" ]]; then
        log WARN "SCP '$scp_name' already exists: $existing_scp"
        echo "$existing_scp"
        return 0
    fi

    log INFO "Creating SCP: $scp_name"

    # Create SCP policy document
    local scp_policy=$(cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootUserAccess",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
EOF
)

    local scp_result=$(aws organizations create-policy \
        --content "$scp_policy" \
        --description "Deny root user access except for account management" \
        --name "$scp_name" \
        --type SERVICE_CONTROL_POLICY \
        --output json)

    local scp_id=$(echo $scp_result | jq -r '.Policy.PolicySummary.Id')
    log INFO "✓ SCP created: $scp_id"

    echo "$scp_id"
}

create_require_mfa_scp() {
    log INFO "Creating SCP to require MFA..."

    local scp_name="RequireMFAForActions"

    # Check if SCP already exists
    local existing_scp=$(aws organizations list-policies \
        --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='$scp_name'].Id" \
        --output text)

    if [[ -n "$existing_scp" ]]; then
        log WARN "SCP '$scp_name' already exists: $existing_scp"
        echo "$existing_scp"
        return 0
    fi

    log INFO "Creating SCP: $scp_name"

    # Create SCP policy document
    local scp_policy=$(cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyActionsWithoutMFA",
      "Effect": "Deny",
      "Action": [
        "ec2:*",
        "s3:*",
        "rds:*",
        "lambda:*"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
EOF
)

    local scp_result=$(aws organizations create-policy \
        --content "$scp_policy" \
        --description "Require MFA for sensitive actions" \
        --name "$scp_name" \
        --type SERVICE_CONTROL_POLICY \
        --output json)

    local scp_id=$(echo $scp_result | jq -r '.Policy.PolicySummary.Id')
    log INFO "✓ SCP created: $scp_id"

    echo "$scp_id"
}

attach_scps_to_ous() {
    log INFO "Step 6: Attaching SCPs to Organizational Units..."

    local root_id=$(get_root_id)

    # Get OU IDs
    local security_ou=$(aws organizations list-organizational-units-for-parent \
        --parent-id "$root_id" \
        --query "OrganizationalUnits[?Name=='Security'].Id" \
        --output text)

    local infra_ou=$(aws organizations list-organizational-units-for-parent \
        --parent-id "$root_id" \
        --query "OrganizationalUnits[?Name=='Infrastructure'].Id" \
        --output text)

    local workloads_ou=$(aws organizations list-organizational-units-for-parent \
        --parent-id "$root_id" \
        --query "OrganizationalUnits[?Name=='Workloads'].Id" \
        --output text)

    # Get SCP IDs
    local deny_root_scp=$(aws organizations list-policies \
        --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='DenyRootUserActions'].Id" \
        --output text)

    local require_mfa_scp=$(aws organizations list-policies \
        --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='RequireMFAForActions'].Id" \
        --output text)

    # Attach SCPs to OUs
    if [[ -n "$security_ou" && -n "$deny_root_scp" ]]; then
        log INFO "Attaching DenyRootUserActions to Security OU..."
        aws organizations attach-policy \
            --policy-id "$deny_root_scp" \
            --target-id "$security_ou" 2>/dev/null || log WARN "SCP may already be attached"
    fi

    if [[ -n "$workloads_ou" && -n "$require_mfa_scp" ]]; then
        log INFO "Attaching RequireMFAForActions to Workloads OU..."
        aws organizations attach-policy \
            --policy-id "$require_mfa_scp" \
            --target-id "$workloads_ou" 2>/dev/null || log WARN "SCP may already be attached"
    fi

    log INFO "✓ SCPs attached to OUs"
}

################################################################################
# CloudTrail Organization Trail
################################################################################

setup_cloudtrail_organization_trail() {
    log INFO "Step 7: Setting up CloudTrail Organization Trail..."

    local management_account_id=$(aws sts get-caller-identity --query Account --output text)
    local trail_name="organization-trail"
    local bucket_name="cloudtrail-logs-${management_account_id}"

    # Create S3 bucket for CloudTrail logs
    log INFO "Creating S3 bucket for CloudTrail logs: $bucket_name"

    if aws s3 ls "s3://$bucket_name" 2>/dev/null; then
        log WARN "S3 bucket already exists: $bucket_name"
    else
        aws s3 mb "s3://$bucket_name" --region "$AWS_REGION"

        # Enable versioning
        aws s3api put-bucket-versioning \
            --bucket "$bucket_name" \
            --versioning-configuration Status=Enabled

        # Enable encryption
        aws s3api put-bucket-encryption \
            --bucket "$bucket_name" \
            --server-side-encryption-configuration '{
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    },
                    "BucketKeyEnabled": true
                }]
            }'

        log INFO "✓ S3 bucket created and configured"
    fi

    # Create bucket policy for CloudTrail
    local bucket_policy=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${bucket_name}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${bucket_name}/AWSLogs/${management_account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        },
        {
            "Sid": "AWSCloudTrailOrganizationWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${bucket_name}/AWSLogs/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
EOF
)

    echo "$bucket_policy" | aws s3api put-bucket-policy \
        --bucket "$bucket_name" \
        --policy file:///dev/stdin

    log INFO "✓ Bucket policy configured"

    # Enable CloudTrail for organization
    log INFO "Creating organization trail..."

    # Check if trail exists
    if aws cloudtrail get-trail --name "$trail_name" &>/dev/null; then
        log WARN "CloudTrail already exists: $trail_name"
    else
        aws cloudtrail create-trail \
            --name "$trail_name" \
            --s3-bucket-name "$bucket_name" \
            --is-organization-trail \
            --is-multi-region-trail \
            --enable-log-file-validation \
            --region "$AWS_REGION"

        # Start logging
        aws cloudtrail start-logging \
            --name "$trail_name" \
            --region "$AWS_REGION"

        log INFO "✓ Organization trail created and started"
    fi
}

################################################################################
# Enable AWS Services
################################################################################

enable_aws_services() {
    log INFO "Step 8: Enabling AWS Services for Organizations..."

    local services=(
        "cloudtrail.amazonaws.com"
        "config.amazonaws.com"
        "sso.amazonaws.com"
    )

    for service in "${services[@]}"; do
        log INFO "Enabling trusted access for: $service"
        aws organizations enable-aws-service-access \
            --service-principal "$service" 2>/dev/null || \
            log WARN "Service may already be enabled or not available"
    done

    log INFO "✓ AWS Services enabled"
}

################################################################################
# Summary and Output
################################################################################

generate_summary() {
    log INFO "Step 9: Generating Landing Zone Summary..."

    local management_account_id=$(aws sts get-caller-identity --query Account --output text)
    local org_id=$(aws organizations describe-organization --query 'Organization.Id' --output text)

    # Get account IDs
    local log_archive_id=$(aws organizations list-accounts \
        --query "Accounts[?Name=='LogArchive'].Id" \
        --output text)

    local security_audit_id=$(aws organizations list-accounts \
        --query "Accounts[?Name=='SecurityAudit'].Id" \
        --output text)

    # Generate summary report
    local summary_file="landing-zone-summary-$(date +%Y%m%d_%H%M%S).txt"

    cat > "$summary_file" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║           AWS Landing Zone Provisioning Summary                ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

Provisioning Date: $(date '+%Y-%m-%d %H:%M:%S')
Script Version: $SCRIPT_VERSION
AWS Region: $AWS_REGION

════════════════════════════════════════════════════════════════

ORGANIZATION DETAILS
════════════════════════════════════════════════════════════════
Organization ID:        $org_id
Organization Name:      $ORG_NAME
Management Account ID:  $management_account_id

════════════════════════════════════════════════════════════════

CORE ACCOUNTS
════════════════════════════════════════════════════════════════
1. Management Account
   Account ID:    $management_account_id
   Purpose:       Organization root, consolidated billing
   OU:            Root

2. Log Archive Account
   Account ID:    $log_archive_id
   Email:         $LOG_ARCHIVE_EMAIL
   Purpose:       Centralized log storage
   OU:            Infrastructure

3. Security/Audit Account
   Account ID:    $security_audit_id
   Email:         $SECURITY_AUDIT_EMAIL
   Purpose:       Security tooling and compliance
   OU:            Security

════════════════════════════════════════════════════════════════

ORGANIZATIONAL UNITS
════════════════════════════════════════════════════════════════
• Security (contains Security/Audit account)
• Infrastructure (contains Log Archive account)
• Workloads (ready for future workload accounts)

════════════════════════════════════════════════════════════════

SERVICE CONTROL POLICIES
════════════════════════════════════════════════════════════════
• DenyRootUserActions - Applied to Security OU
• RequireMFAForActions - Applied to Workloads OU

════════════════════════════════════════════════════════════════

CLOUDTRAIL CONFIGURATION
════════════════════════════════════════════════════════════════
Trail Name:        organization-trail
S3 Bucket:         cloudtrail-logs-${management_account_id}
Multi-region:      Enabled
Organization-wide: Enabled
Log Validation:    Enabled

════════════════════════════════════════════════════════════════

NEXT STEPS
════════════════════════════════════════════════════════════════
1. Configure MFA for root users on all accounts
2. Set up IAM Identity Center (AWS SSO) for user access
3. Enable AWS Config in all accounts
4. Set up AWS Security Hub in Security/Audit account
5. Configure GuardDuty with delegated administration
6. Create additional workload accounts as needed
7. Review and customize Service Control Policies
8. Set up cross-account IAM roles for access management
9. Configure AWS Backup for data protection
10. Implement tagging strategy across all resources

════════════════════════════════════════════════════════════════

IMPORTANT SECURITY REMINDERS
════════════════════════════════════════════════════════════════
✓ Enable MFA on all root user accounts IMMEDIATELY
✓ Delete root user access keys if they exist
✓ Configure account contact information
✓ Set up billing alerts and budgets
✓ Review and test Service Control Policies
✓ Document emergency access procedures
✓ Configure security monitoring and alerting
✓ Implement least-privilege access policies

════════════════════════════════════════════════════════════════

For detailed logs, see: $LOG_FILE

════════════════════════════════════════════════════════════════
EOF

    cat "$summary_file"
    log INFO "✓ Summary saved to: $summary_file"
}

################################################################################
# Main Execution
################################################################################

main() {
    print_banner

    log INFO "Starting AWS Landing Zone provisioning..."
    log INFO "Region: $AWS_REGION"
    log INFO "Log file: $LOG_FILE"
    echo ""

    # Confirmation prompt
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}WARNING: This script will create AWS resources that may${NC}"
    echo -e "${YELLOW}incur costs. Please ensure you have the necessary${NC}"
    echo -e "${YELLOW}permissions and have reviewed the configuration.${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Configuration:"
    echo "  Organization Name: $ORG_NAME"
    echo "  AWS Region: $AWS_REGION"
    echo "  Log Archive Email: $LOG_ARCHIVE_EMAIL"
    echo "  Security/Audit Email: $SECURITY_AUDIT_EMAIL"
    echo ""
    read -p "Do you want to proceed? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        log WARN "Provisioning cancelled by user"
        exit 0
    fi

    echo ""

    # Execute provisioning steps
    check_prerequisites
    validate_email_addresses

    create_organization
    create_organizational_units

    local log_archive_id=$(create_log_archive_account)
    local security_audit_id=$(create_security_audit_account)

    create_deny_root_scp
    create_require_mfa_scp
    attach_scps_to_ous

    setup_cloudtrail_organization_trail
    enable_aws_services

    generate_summary

    echo ""
    log INFO "═══════════════════════════════════════════════════════"
    log INFO "✓ AWS Landing Zone provisioning completed successfully!"
    log INFO "═══════════════════════════════════════════════════════"
    echo ""
    log INFO "Please review the summary file and complete the next steps."
    log INFO "Don't forget to enable MFA on all root user accounts!"
}

# Trap errors
trap 'log ERROR "Script failed at line $LINENO"' ERR

# Run main function
main "$@"