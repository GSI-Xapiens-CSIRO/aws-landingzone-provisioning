#!/bin/bash

################################################################################
# AWS Landing Zone Provisioning Script
# Version: 3.0.0
# Description: End-to-end AWS Landing Zone provisioning with Control Tower concepts
#              Includes proper trust policies and cross-account access setup
#
# Features:
#   - AWS Organizations creation
#   - Core account provisioning (Log Archive, Security/Audit)
#   - Hub accounts (Production genomics workloads)
#   - UAT accounts (Staging/Testing genomics workloads)
#   - Organizational Units structure
#   - Service Control Policies
#   - CloudTrail organization trail
#   - Cross-account access configuration
#   - Trust policy setup for OrganizationAccountAccessRole
#
# Author: DevOps Team
# Date: 2025-11-17
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
NC='\033[0m' # No Color

# Configuration
SCRIPT_VERSION="3.0.0"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create results directory structure
RESULTS_DIR="${SCRIPT_DIR}/results"
LOGS_DIR="${RESULTS_DIR}/logs"
SUMMARY_DIR="${RESULTS_DIR}/summary"
CONFIGS_DIR="${RESULTS_DIR}/configs"

mkdir -p "${LOGS_DIR}" "${SUMMARY_DIR}" "${CONFIGS_DIR}"

LOG_FILE="${LOGS_DIR}/landing-zone-provisioning-${TIMESTAMP}.log"
ORG_NAME="${ORG_NAME:-BB BINOMIKA}"
AWS_REGION="${AWS_REGION:-ap-southeast-3}"

# Email addresses for account root users (MUST BE UNIQUE)
LOG_ARCHIVE_EMAIL="${LOG_ARCHIVE_EMAIL}"
SECURITY_AUDIT_EMAIL="${SECURITY_AUDIT_EMAIL}"

# Account creation tracking
declare -A CREATED_ACCOUNTS
ACCOUNT_IDS_FILE="${CONFIGS_DIR}/account-ids-${TIMESTAMP}.json"

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
        SUCCESS)
            echo -e "${CYAN}[${timestamp}] [SUCCESS]${NC} ${message}" | tee -a "$LOG_FILE"
            ;;
    esac
}

print_banner() {
    echo -e "${BLUE}"
    cat << EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║     AWS Landing Zone Provisioning Script v${SCRIPT_VERSION}                ║
║                                                                ║
║  Creating comprehensive multi-account AWS environment with:    ║
║    • AWS Organizations with ALL features                       ║
║    • Core Organizational Units (OUs)                           ║
║    • Log Archive Account (centralized logging)                 ║
║    • Security/Audit Account (security tooling)                 ║
║    • Hub Accounts (production genomics workloads)              ║
║    • UAT Accounts (staging genomics workloads)                 ║
║    • Service Control Policies (SCPs)                           ║
║    • CloudTrail Organization Trail                             ║
║    • Cross-Account Access Configuration                        ║
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
# Pre-flight Checks
################################################################################

check_prerequisites() {
    print_section "Pre-Flight Checks"

    log INFO "Running pre-flight checks..."

    # Check AWS CLI installation
    if ! command -v aws &> /dev/null; then
        log ERROR "AWS CLI is not installed. Please install it first."
        exit 1
    fi

    # Check AWS CLI version (require v2)
    local aws_version=$(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1 | cut -d. -f1)
    if [ "$aws_version" -lt 2 ]; then
        log ERROR "AWS CLI version 2 or higher is required. Current: $(aws --version)"
        exit 1
    fi
    log INFO "✓ AWS CLI version: $(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)"

    # Check jq installation
    if ! command -v jq &> /dev/null; then
        log ERROR "jq is not installed. Please install it: sudo apt-get install jq"
        exit 1
    fi
    log INFO "✓ jq installed"

    # Verify AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log ERROR "AWS credentials are not configured or invalid"
        log ERROR "Run: aws configure"
        exit 1
    fi

    # Get caller identity
    local caller_identity=$(aws sts get-caller-identity --output json)
    local account_id=$(echo $caller_identity | jq -r '.Account')
    local user_arn=$(echo $caller_identity | jq -r '.Arn')

    log INFO "✓ Authenticated as: $user_arn"
    log INFO "✓ Management Account ID: $account_id"

    # Save management account ID
    MANAGEMENT_ACCOUNT_ID="$account_id"

    log SUCCESS "All prerequisites met"
}

validate_email_addresses() {
    log INFO "Validating email addresses..."

    if [[ "$LOG_ARCHIVE_EMAIL" == *"example.com"* ]] || [[ "$SECURITY_AUDIT_EMAIL" == *"example.com"* ]]; then
        log ERROR "Please set valid email addresses in .env file"
        exit 1
    fi

    if [[ "$LOG_ARCHIVE_EMAIL" == "$SECURITY_AUDIT_EMAIL" ]]; then
        log ERROR "Email addresses must be unique for each account"
        exit 1
    fi

    log SUCCESS "Email addresses validated"
}

################################################################################
# AWS Organizations Setup
################################################################################

create_organization() {
    print_section "Step 1: AWS Organization Setup"

    log INFO "Creating/Verifying AWS Organization..."

    # Check if organization already exists
    if aws organizations describe-organization &> /dev/null 2>&1; then
        log WARN "Organization already exists"
        local org_id=$(aws organizations describe-organization --query 'Organization.Id' --output text)
        local feature_set=$(aws organizations describe-organization --query 'Organization.FeatureSet' --output text)

        log INFO "Organization ID: $org_id"
        log INFO "Feature Set: $feature_set"

        # Ensure ALL features are enabled
        if [[ "$feature_set" != "ALL" ]]; then
            log ERROR "Organization exists but doesn't have ALL features enabled"
            log ERROR "Cannot enable SCPs and other advanced features"
            log ERROR "Please enable all features manually first"
            exit 1
        fi

        return 0
    fi

    # Create organization with all features enabled
    log INFO "Creating new organization with ALL features enabled..."
    local org_result=$(aws organizations create-organization \
        --feature-set ALL \
        --output json)

    local org_id=$(echo $org_result | jq -r '.Organization.Id')
    log SUCCESS "Organization created successfully"
    log INFO "Organization ID: $org_id"

    # Wait for organization to be fully ready
    sleep 5
}

get_root_id() {
    aws organizations list-roots --query 'Roots[0].Id' --output text
}

################################################################################
# Organizational Units (OUs) Creation
################################################################################

create_organizational_units() {
    print_section "Step 2: Creating Organizational Units"

    log INFO "Creating Organizational Units (OUs)..."

    local root_id=$(get_root_id)
    log INFO "Root ID: $root_id"

    # Function to create or get existing OU
    create_or_get_ou() {
        local ou_name=$1
        local parent_id=$2

        # Check if OU already exists
        local existing_ou=$(aws organizations list-organizational-units-for-parent \
            --parent-id "$parent_id" \
            --query "OrganizationalUnits[?Name=='$ou_name'].Id" \
            --output text 2>/dev/null || echo "")

        if [[ -n "$existing_ou" ]]; then
            log INFO "✓ $ou_name OU already exists: $existing_ou"
            echo "$existing_ou"
        else
            # Create new OU
            local new_ou=$(aws organizations create-organizational-unit \
                --parent-id "$parent_id" \
                --name "$ou_name" \
                --query 'OrganizationalUnit.Id' \
                --output text)
            log SUCCESS "✓ Created $ou_name OU: $new_ou"
            echo "$new_ou"
        fi
    }

    # Create Security OU
    SECURITY_OU_ID=$(create_or_get_ou "Security" "$root_id")

    # Create Infrastructure OU
    INFRASTRUCTURE_OU_ID=$(create_or_get_ou "Infrastructure" "$root_id")

    # Create Workloads OU (for future use)
    WORKLOADS_OU_ID=$(create_or_get_ou "Workloads" "$root_id")

    # Create Hub OU for production genomics workloads
    HUB_OU_ID=$(create_or_get_ou "Hub-Production" "$root_id")

    # Create UAT OU for staging genomics workloads
    UAT_OU_ID=$(create_or_get_ou "UAT-Staging" "$root_id")

    log SUCCESS "All Organizational Units created/verified"
}

################################################################################
# Core Account Creation with Proper Error Handling
################################################################################

wait_for_account_creation() {
    local request_id=$1
    local account_name=$2
    local max_attempts=60
    local attempt=0

    log INFO "Waiting for account creation to complete: $account_name"
    log INFO "Request ID: $request_id"

    while [ $attempt -lt $max_attempts ]; do
        local status=$(aws organizations describe-create-account-status \
            --create-account-request-id "$request_id" \
            --query 'CreateAccountStatus.State' \
            --output text)

        case "$status" in
            SUCCEEDED)
                local account_id=$(aws organizations describe-create-account-status \
                    --create-account-request-id "$request_id" \
                    --query 'CreateAccountStatus.AccountId' \
                    --output text)
                log SUCCESS "Account created successfully: $account_name (ID: $account_id)"
                echo "$account_id"
                return 0
                ;;
            FAILED)
                local reason=$(aws organizations describe-create-account-status \
                    --create-account-request-id "$request_id" \
                    --query 'CreateAccountStatus.FailureReason' \
                    --output text)
                log ERROR "Account creation failed: $account_name"
                log ERROR "Reason: $reason"
                return 1
                ;;
            IN_PROGRESS)
                echo -n "."
                sleep 10
                ((attempt++))
                ;;
        esac
    done

    log ERROR "Timeout waiting for account creation: $account_name"
    return 1
}

create_account_with_retry() {
    local account_name=$1
    local account_email=$2
    local target_ou_id=$3
    local max_retries=3
    local retry=0

    log INFO "Creating account: $account_name"
    log INFO "Email: $account_email"

    # Check if account already exists
    local existing_account=$(aws organizations list-accounts \
        --query "Accounts[?Name=='$account_name'].Id" \
        --output text 2>/dev/null || echo "")

    if [[ -n "$existing_account" ]]; then
        log WARN "Account already exists: $account_name (ID: $existing_account)"

        # Move to correct OU if needed
        if [[ -n "$target_ou_id" ]]; then
            local current_parent=$(aws organizations list-parents \
                --child-id "$existing_account" \
                --query 'Parents[0].Id' \
                --output text)

            if [[ "$current_parent" != "$target_ou_id" ]]; then
                log INFO "Moving account to correct OU..."
                aws organizations move-account \
                    --account-id "$existing_account" \
                    --source-parent-id "$current_parent" \
                    --destination-parent-id "$target_ou_id" 2>/dev/null || \
                    log WARN "Could not move account to OU"
            fi
        fi

        CREATED_ACCOUNTS["$account_name"]="$existing_account"
        echo "$existing_account"
        return 0
    fi

    while [ $retry -lt $max_retries ]; do
        log INFO "Attempt $((retry + 1))/$max_retries"

        # Create account
        local create_result=$(aws organizations create-account \
            --email "$account_email" \
            --account-name "$account_name" \
            --output json 2>&1)

        if [[ $? -ne 0 ]]; then
            log WARN "Account creation request failed: $create_result"
            ((retry++))
            sleep 5
            continue
        fi

        local request_id=$(echo "$create_result" | jq -r '.CreateAccountStatus.Id')

        # Wait for account creation
        local account_id=$(wait_for_account_creation "$request_id" "$account_name")

        if [[ -n "$account_id" ]]; then
            # Move to target OU if specified
            if [[ -n "$target_ou_id" ]]; then
                log INFO "Moving account to OU..."
                sleep 5  # Wait for account to be fully ready

                local root_id=$(get_root_id)
                if aws organizations move-account \
                    --account-id "$account_id" \
                    --source-parent-id "$root_id" \
                    --destination-parent-id "$target_ou_id" 2>&1; then
                    log SUCCESS "Account moved to OU successfully"
                else
                    log WARN "Could not move account to OU immediately (may need manual intervention)"
                fi
            fi

            CREATED_ACCOUNTS["$account_name"]="$account_id"
            echo "$account_id"
            return 0
        fi

        ((retry++))
        sleep 10
    done

    log ERROR "Failed to create account after $max_retries attempts: $account_name"
    return 1
}

################################################################################
# Core Accounts Creation
################################################################################

create_log_archive_account() {
    print_section "Step 3: Creating Log Archive Account"

    local account_id=$(create_account_with_retry "LogArchive" "$LOG_ARCHIVE_EMAIL" "$INFRASTRUCTURE_OU_ID")

    if [[ -z "$account_id" ]]; then
        log ERROR "Failed to create Log Archive account"
        exit 1
    fi

    log SUCCESS "Log Archive account created: $account_id"
    echo "$account_id"
}

create_security_audit_account() {
    print_section "Step 4: Creating Security/Audit Account"

    local account_id=$(create_account_with_retry "SecurityAudit" "$SECURITY_AUDIT_EMAIL" "$SECURITY_OU_ID")

    if [[ -z "$account_id" ]]; then
        log ERROR "Failed to create Security/Audit account"
        exit 1
    fi

    log SUCCESS "Security/Audit account created: $account_id"
    echo "$account_id"
}

################################################################################
# Hub Accounts Creation (Production)
################################################################################

create_hub_accounts() {
    print_section "Step 5: Creating Hub Accounts (Production Genomics)"

    # Hub01 - RSCM (Production)
    if [[ -n "${AWS_PROFILE_HUB01_EMAIL:-}" ]]; then
        log INFO "Creating Hub01-RSCM account..."
        local hub01_id=$(create_account_with_retry "Hub01-RSCM" "$AWS_PROFILE_HUB01_EMAIL" "$HUB_OU_ID")
        [[ -n "$hub01_id" ]] && log SUCCESS "Hub01-RSCM created: $hub01_id"
    fi

    # Hub02 - RSPON (Production)
    if [[ -n "${AWS_PROFILE_HUB02_EMAIL:-}" ]]; then
        log INFO "Creating Hub02-RSPON account..."
        local hub02_id=$(create_account_with_retry "Hub02-RSPON" "$AWS_PROFILE_HUB02_EMAIL" "$HUB_OU_ID")
        [[ -n "$hub02_id" ]] && log SUCCESS "Hub02-RSPON created: $hub02_id"
    fi

    # Hub03 - SARDJITO (Production)
    if [[ -n "${AWS_PROFILE_HUB03_EMAIL:-}" ]]; then
        log INFO "Creating Hub03-SARDJITO account..."
        local hub03_id=$(create_account_with_retry "Hub03-SARDJITO" "$AWS_PROFILE_HUB03_EMAIL" "$HUB_OU_ID")
        [[ -n "$hub03_id" ]] && log SUCCESS "Hub03-SARDJITO created: $hub03_id"
    fi

    # Hub04 - RSNGOERAH (Production)
    if [[ -n "${AWS_PROFILE_HUB04_EMAIL:-}" ]]; then
        log INFO "Creating Hub04-RSNGOERAH account..."
        local hub04_id=$(create_account_with_retry "Hub04-RSNGOERAH" "$AWS_PROFILE_HUB04_EMAIL" "$HUB_OU_ID")
        [[ -n "$hub04_id" ]] && log SUCCESS "Hub04-RSNGOERAH created: $hub04_id"
    fi

    # Hub05 - RSJPD (Production)
    if [[ -n "${AWS_PROFILE_HUB05_EMAIL:-}" ]]; then
        log INFO "Creating Hub05-RSJPD account..."
        local hub05_id=$(create_account_with_retry "Hub05-RSJPD" "$AWS_PROFILE_HUB05_EMAIL" "$HUB_OU_ID")
        [[ -n "$hub05_id" ]] && log SUCCESS "Hub05-RSJPD created: $hub05_id"
    fi
}

################################################################################
# UAT Accounts Creation (Staging)
################################################################################

create_uat_accounts() {
    print_section "Step 6: Creating UAT Accounts (Staging Genomics)"

    # UAT01 - RSCM (Staging)
    if [[ -n "${AWS_PROFILE_UAT01_EMAIL:-}" ]]; then
        log INFO "Creating UAT01-RSCM account..."
        local uat01_id=$(create_account_with_retry "UAT01-RSCM" "$AWS_PROFILE_UAT01_EMAIL" "$UAT_OU_ID")
        [[ -n "$uat01_id" ]] && log SUCCESS "UAT01-RSCM created: $uat01_id"
    fi

    # UAT02 - RSPON (Staging)
    if [[ -n "${AWS_PROFILE_UAT02_EMAIL:-}" ]]; then
        log INFO "Creating UAT02-RSPON account..."
        local uat02_id=$(create_account_with_retry "UAT02-RSPON" "$AWS_PROFILE_UAT02_EMAIL" "$UAT_OU_ID")
        [[ -n "$uat02_id" ]] && log SUCCESS "UAT02-RSPON created: $uat02_id"
    fi

    # UAT03 - SARDJITO (Staging)
    if [[ -n "${AWS_PROFILE_UAT03_EMAIL:-}" ]]; then
        log INFO "Creating UAT03-SARDJITO account..."
        local uat03_id=$(create_account_with_retry "UAT03-SARDJITO" "$AWS_PROFILE_UAT03_EMAIL" "$UAT_OU_ID")
        [[ -n "$uat03_id" ]] && log SUCCESS "UAT03-SARDJITO created: $uat03_id"
    fi

    # UAT04 - RSNGOERAH (Staging)
    if [[ -n "${AWS_PROFILE_UAT04_EMAIL:-}" ]]; then
        log INFO "Creating UAT04-RSNGOERAH account..."
        local uat04_id=$(create_account_with_retry "UAT04-RSNGOERAH" "$AWS_PROFILE_UAT04_EMAIL" "$UAT_OU_ID")
        [[ -n "$uat04_id" ]] && log SUCCESS "UAT04-RSNGOERAH created: $uat04_id"
    fi

    # UAT05 - RSJPD (Staging)
    if [[ -n "${AWS_PROFILE_UAT05_EMAIL:-}" ]]; then
        log INFO "Creating UAT05-RSJPD account..."
        local uat05_id=$(create_account_with_retry "UAT05-RSJPD" "$AWS_PROFILE_UAT05_EMAIL" "$UAT_OU_ID")
        [[ -n "$uat05_id" ]] && log SUCCESS "UAT05-RSJPD created: $uat05_id"
    fi
}

################################################################################
# Service Control Policies (SCPs)
################################################################################

create_deny_root_scp() {
    print_section "Step 7: Creating Service Control Policies"

    log INFO "Creating DenyRootUserActions SCP..."

    # Check if SCP already exists
    local existing_scp=$(aws organizations list-policies \
        --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='DenyRootUserActions'].Id" \
        --output text 2>/dev/null || echo "")

    if [[ -n "$existing_scp" ]]; then
        log WARN "DenyRootUserActions SCP already exists: $existing_scp"
        SCP_DENY_ROOT_ID="$existing_scp"
        return 0
    fi

    # Create SCP
    local scp_content=$(cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
        --content "$scp_content" \
        --description "Deny all actions for root user" \
        --name "DenyRootUserActions" \
        --type SERVICE_CONTROL_POLICY \
        --output json)

    SCP_DENY_ROOT_ID=$(echo "$scp_result" | jq -r '.Policy.PolicySummary.Id')
    log SUCCESS "DenyRootUserActions SCP created: $SCP_DENY_ROOT_ID"
}

create_require_mfa_scp() {
    log INFO "Creating RequireMFAForActions SCP..."

    # Check if SCP already exists
    local existing_scp=$(aws organizations list-policies \
        --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='RequireMFAForActions'].Id" \
        --output text 2>/dev/null || echo "")

    if [[ -n "$existing_scp" ]]; then
        log WARN "RequireMFAForActions SCP already exists: $existing_scp"
        SCP_REQUIRE_MFA_ID="$existing_scp"
        return 0
    fi

    local scp_content=$(cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:StopInstances",
        "ec2:TerminateInstances",
        "rds:DeleteDBInstance",
        "rds:DeleteDBCluster",
        "s3:DeleteBucket",
        "dynamodb:DeleteTable"
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
        --content "$scp_content" \
        --description "Require MFA for destructive actions" \
        --name "RequireMFAForActions" \
        --type SERVICE_CONTROL_POLICY \
        --output json)

    SCP_REQUIRE_MFA_ID=$(echo "$scp_result" | jq -r '.Policy.PolicySummary.Id')
    log SUCCESS "RequireMFAForActions SCP created: $SCP_REQUIRE_MFA_ID"
}

attach_scps_to_ous() {
    log INFO "Attaching SCPs to Organizational Units..."

    # Attach DenyRootUserActions to Security OU
    if [[ -n "${SCP_DENY_ROOT_ID:-}" ]] && [[ -n "${SECURITY_OU_ID:-}" ]]; then
        aws organizations attach-policy \
            --policy-id "$SCP_DENY_ROOT_ID" \
            --target-id "$SECURITY_OU_ID" 2>/dev/null || \
            log WARN "SCP may already be attached to Security OU"
        log SUCCESS "DenyRootUserActions attached to Security OU"
    fi

    # Attach RequireMFAForActions to Workloads OU
    if [[ -n "${SCP_REQUIRE_MFA_ID:-}" ]] && [[ -n "${WORKLOADS_OU_ID:-}" ]]; then
        aws organizations attach-policy \
            --policy-id "$SCP_REQUIRE_MFA_ID" \
            --target-id "$WORKLOADS_OU_ID" 2>/dev/null || \
            log WARN "SCP may already be attached to Workloads OU"
        log SUCCESS "RequireMFAForActions attached to Workloads OU"
    fi
}

################################################################################
# CloudTrail Organization Trail
################################################################################

setup_cloudtrail_organization_trail() {
    print_section "Step 8: Setting Up CloudTrail Organization Trail"

    log INFO "Configuring CloudTrail organization-wide logging..."

    local trail_name="organization-trail"
    local bucket_name="cloudtrail-logs-${MANAGEMENT_ACCOUNT_ID}"

    # Create S3 bucket for CloudTrail
    log INFO "Creating S3 bucket for CloudTrail: $bucket_name"

    if aws s3 ls "s3://$bucket_name" &>/dev/null; then
        log WARN "S3 bucket already exists: $bucket_name"
    else
        # Create bucket
        if [[ "$AWS_REGION" == "us-east-1" ]]; then
            aws s3api create-bucket \
                --bucket "$bucket_name" \
                --region "$AWS_REGION"
        else
            aws s3api create-bucket \
                --bucket "$bucket_name" \
                --region "$AWS_REGION" \
                --create-bucket-configuration LocationConstraint="$AWS_REGION"
        fi

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
                    }
                }]
            }'

        log SUCCESS "S3 bucket created: $bucket_name"
    fi

    # Set bucket policy for CloudTrail
    log INFO "Configuring bucket policy for CloudTrail..."

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

    echo "$bucket_policy" > /tmp/cloudtrail-bucket-policy.json
    aws s3api put-bucket-policy \
        --bucket "$bucket_name" \
        --policy file:///tmp/cloudtrail-bucket-policy.json
    rm /tmp/cloudtrail-bucket-policy.json

    # Create or update CloudTrail
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

        log SUCCESS "Organization trail created and started"
    fi
}

################################################################################
# Enable AWS Services
################################################################################

enable_aws_services() {
    print_section "Step 9: Enabling AWS Services"

    log INFO "Enabling AWS Services for Organizations..."

    local services=(
        "cloudtrail.amazonaws.com"
        "config.amazonaws.com"
        "sso.amazonaws.com"
        "controltower.amazonaws.com"
    )

    for service in "${services[@]}"; do
        log INFO "Enabling trusted access for: $service"
        aws organizations enable-aws-service-access \
            --service-principal "$service" 2>/dev/null || \
            log WARN "Service may already be enabled: $service"
    done

    log SUCCESS "AWS Services enabled"
}

################################################################################
# Cross-Account Access Setup
################################################################################

setup_cross_account_access() {
    print_section "Step 10: Setting Up Cross-Account Access"

    log INFO "Configuring OrganizationAccountAccessRole trust policies..."
    log WARN "This step requires manual configuration for security reasons"

    # Generate trust policy setup script
    local setup_script="${CONFIGS_DIR}/setup-cross-account-access.sh"

    cat > "$setup_script" <<'SCRIPT_EOF'
#!/bin/bash

# Setup Cross-Account Access for Post-Deployment Automation
# This script configures OrganizationAccountAccessRole trust policies

set -e

MANAGEMENT_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "Management Account: $MANAGEMENT_ACCOUNT_ID"
echo ""
echo "This script will update trust policies for OrganizationAccountAccessRole"
echo "in member accounts to allow access from the management account."
echo ""

# Get all member accounts
ACCOUNTS=$(aws organizations list-accounts \
    --query 'Accounts[?Status==`ACTIVE` && Id!=`'$MANAGEMENT_ACCOUNT_ID'`].[Id,Name]' \
    --output json)

echo "Found $(echo "$ACCOUNTS" | jq 'length') member accounts"
echo ""

# Trust policy template
create_trust_policy() {
    local account_id=$1
    cat > /tmp/trust-policy-${account_id}.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${MANAGEMENT_ACCOUNT_ID}:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# Process each account
echo "$ACCOUNTS" | jq -c '.[]' | while read -r account; do
    ACCOUNT_ID=$(echo "$account" | jq -r '.[0]')
    ACCOUNT_NAME=$(echo "$account" | jq -r '.[1]')

    echo "Processing: $ACCOUNT_NAME ($ACCOUNT_ID)"

    # Assume role in the account
    CREDENTIALS=$(aws sts assume-role \
        --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/OrganizationAccountAccessRole" \
        --role-session-name "TrustPolicyUpdate" \
        --output json 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "  ✗ Cannot assume role in $ACCOUNT_NAME - skipping"
        continue
    fi

    # Export temporary credentials
    export AWS_ACCESS_KEY_ID=$(echo "$CREDENTIALS" | jq -r '.Credentials.AccessKeyId')
    export AWS_SECRET_ACCESS_KEY=$(echo "$CREDENTIALS" | jq -r '.Credentials.SecretAccessKey')
    export AWS_SESSION_TOKEN=$(echo "$CREDENTIALS" | jq -r '.Credentials.SessionToken')

    # Update trust policy
    create_trust_policy "$ACCOUNT_ID"

    aws iam update-assume-role-policy \
        --role-name OrganizationAccountAccessRole \
        --policy-document file:///tmp/trust-policy-${ACCOUNT_ID}.json 2>/dev/null

    if [[ $? -eq 0 ]]; then
        echo "  ✓ Trust policy updated for $ACCOUNT_NAME"
    else
        echo "  ✗ Failed to update trust policy for $ACCOUNT_NAME"
    fi

    # Clean up credentials
    unset AWS_ACCESS_KEY_ID
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_SESSION_TOKEN

    rm -f /tmp/trust-policy-${ACCOUNT_ID}.json
done

echo ""
echo "Done! Trust policies updated for all accessible accounts."
SCRIPT_EOF

    chmod +x "$setup_script"

    log SUCCESS "Cross-account access setup script created: $setup_script"
    log WARN "Run this script after accounts are fully provisioned:"
    log WARN "  $setup_script"
}

################################################################################
# Save Account Information
################################################################################

save_account_information() {
    log INFO "Saving account information..."

    # Get all accounts in the organization
    local accounts=$(aws organizations list-accounts --output json)

    # Save to JSON file
    echo "$accounts" | jq '.' > "$ACCOUNT_IDS_FILE"

    log SUCCESS "Account information saved to: $ACCOUNT_IDS_FILE"
}

################################################################################
# Summary and Output
################################################################################

generate_summary() {
    print_section "Step 11: Generating Landing Zone Summary"

    log INFO "Generating Landing Zone Summary..."

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
    local summary_file="${SUMMARY_DIR}/landing-zone-summary-${TIMESTAMP}.txt"

    cat > "$summary_file" << EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║         AWS Landing Zone Provisioning Summary v${SCRIPT_VERSION}           ║
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

HUB ACCOUNTS (Production Genomics Workloads)
════════════════════════════════════════════════════════════════
EOF

    # Add Hub accounts if they exist
    for hub_name in "Hub01-RSCM" "Hub02-RSPON" "Hub03-SARDJITO" "Hub04-RSNGOERAH" "Hub05-RSJPD"; do
        local hub_id=$(aws organizations list-accounts \
            --query "Accounts[?Name=='$hub_name'].Id" \
            --output text 2>/dev/null || echo "Not Created")

        if [[ "$hub_id" != "Not Created" ]]; then
            echo "• $hub_name: $hub_id" >> "$summary_file"
        fi
    done

    cat >> "$summary_file" <<EOF

════════════════════════════════════════════════════════════════

UAT ACCOUNTS (Staging Genomics Workloads)
════════════════════════════════════════════════════════════════
EOF

    # Add UAT accounts if they exist
    for uat_name in "UAT01-RSCM" "UAT02-RSPON" "UAT03-SARDJITO" "UAT04-RSNGOERAH" "UAT05-RSJPD"; do
        local uat_id=$(aws organizations list-accounts \
            --query "Accounts[?Name=='$uat_name'].Id" \
            --output text 2>/dev/null || echo "Not Created")

        if [[ "$uat_id" != "Not Created" ]]; then
            echo "• $uat_name: $uat_id" >> "$summary_file"
        fi
    done

    cat >> "$summary_file" <<EOF

════════════════════════════════════════════════════════════════

ORGANIZATIONAL UNITS
════════════════════════════════════════════════════════════════
• Security (contains Security/Audit account)
• Infrastructure (contains Log Archive account)
• Hub-Production (contains Hub genomics accounts)
• UAT-Staging (contains UAT genomics accounts)
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

CRITICAL NEXT STEPS
════════════════════════════════════════════════════════════════
1. Configure MFA for root users on ALL accounts (HIGHEST PRIORITY)
2. Run cross-account access setup script:
   ${CONFIGS_DIR}/setup-cross-account-access.sh
3. Set up IAM Identity Center (AWS SSO) for user access
4. Enable AWS Config in all accounts
5. Set up AWS Security Hub in Security/Audit account
6. Configure GuardDuty with delegated administration
7. Create workload accounts as needed
8. Review and customize Service Control Policies
9. Set up cross-account IAM roles for access management
10. Configure AWS Backup for data protection

════════════════════════════════════════════════════════════════

IMPORTANT FILES GENERATED
════════════════════════════════════════════════════════════════
• Landing Zone Summary: $summary_file
• Account IDs JSON: $ACCOUNT_IDS_FILE
• Cross-Account Setup Script: ${CONFIGS_DIR}/setup-cross-account-access.sh
• Detailed Log: $LOG_FILE

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
✓ Run the cross-account access setup script

════════════════════════════════════════════════════════════════

For detailed logs, see: $LOG_FILE

════════════════════════════════════════════════════════════════
EOF

    cat "$summary_file"
    log SUCCESS "Summary saved to: $summary_file"
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

    create_hub_accounts
    create_uat_accounts

    create_deny_root_scp
    create_require_mfa_scp
    attach_scps_to_ous

    setup_cloudtrail_organization_trail
    enable_aws_services

    setup_cross_account_access
    save_account_information

    generate_summary

    echo ""
    log SUCCESS "═══════════════════════════════════════════════════════"
    log SUCCESS "✓ AWS Landing Zone provisioning completed successfully!"
    log SUCCESS "═══════════════════════════════════════════════════════"
    echo ""
    log INFO "Please review the summary file and complete the next steps."
    log WARN "Don't forget to enable MFA on all root user accounts!"
    log WARN "Run the cross-account access setup script next:"
    log WARN "  ${CONFIGS_DIR}/setup-cross-account-access.sh"
}

# Trap errors
trap 'log ERROR "Script failed at line $LINENO. Check $LOG_FILE for details."' ERR

# Run main function
main "$@"