#!/bin/bash

################################################################################
# AWS Landing Zone Verification Script
# Version: 3.0.0
# Description: Comprehensive verification of AWS Landing Zone including
#              cross-account access, trust policies, and SSO integration
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
NC='\033[0m'

SCRIPT_VERSION="3.0.0"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create results directory structure
RESULTS_DIR="${SCRIPT_DIR}/results"
LOGS_DIR="${RESULTS_DIR}/logs"
SUMMARY_DIR="${RESULTS_DIR}/summary"
REPORTS_DIR="${RESULTS_DIR}/reports"

mkdir -p "${LOGS_DIR}" "${SUMMARY_DIR}" "${REPORTS_DIR}"

LOG_FILE="${LOGS_DIR}/verify-landing-zone-${TIMESTAMP}.log"
CROSS_ACCOUNT_REPORT="${REPORTS_DIR}/cross-account-access-${TIMESTAMP}.json"

CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNING=0

# Cross-account access tracking
declare -A CROSS_ACCOUNT_RESULTS
declare -A ACCOUNT_NAMES

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "${BLUE}"
    cat << EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    AWS Landing Zone Comprehensive Verification v${SCRIPT_VERSION}          ║
║                                                                ║
║    ✓ Organization Structure                                    ║
║    ✓ Core Accounts                                             ║
║    ✓ Service Control Policies                                  ║
║    ✓ CloudTrail & Logging                                      ║
║    ✓ Cross-Account Access                                      ║
║    ✓ Trust Policy Validation                                   ║
║    ✓ Security Posture                                          ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_section() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$LOG_FILE"
    echo -e "${CYAN}$1${NC}" | tee -a "$LOG_FILE"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$LOG_FILE"
}

check_pass() {
    echo -e "${GREEN}✓${NC} $1" | tee -a "$LOG_FILE"
    ((CHECKS_PASSED++))
}

check_fail() {
    echo -e "${RED}✗${NC} $1" | tee -a "$LOG_FILE"
    ((CHECKS_FAILED++))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1" | tee -a "$LOG_FILE"
    ((CHECKS_WARNING++))
}

check_info() {
    echo -e "${BLUE}ℹ${NC} $1" | tee -a "$LOG_FILE"
}

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

################################################################################
# Verification Checks
################################################################################

verify_prerequisites() {
    print_section "1. Verifying Prerequisites"

    # Check AWS CLI
    if command -v aws &> /dev/null; then
        local version=$(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)
        check_pass "AWS CLI installed (version: $version)"
    else
        check_fail "AWS CLI not found"
        exit 1
    fi

    # Check jq
    if command -v jq &> /dev/null; then
        check_pass "jq installed"
    else
        check_fail "jq not found - required for JSON parsing"
        exit 1
    fi

    # Check AWS credentials
    if aws sts get-caller-identity &> /dev/null; then
        local account_id=$(aws sts get-caller-identity --query Account --output text)
        local user_arn=$(aws sts get-caller-identity --query Arn --output text)
        local user_type=""

        if [[ "$user_arn" == *"assumed-role"* ]]; then
            user_type="Federated SSO User"
        elif [[ "$user_arn" == *":user/"* ]]; then
            user_type="IAM User"
        elif [[ "$user_arn" == *":root" ]]; then
            user_type="Root User"
        else
            user_type="Unknown"
        fi

        check_pass "AWS credentials valid"
        check_info "Account: $account_id"
        check_info "User: $user_arn"
        check_info "Type: $user_type"

        # Store management account ID
        MANAGEMENT_ACCOUNT_ID="$account_id"
        CURRENT_USER_ARN="$user_arn"
    else
        check_fail "AWS credentials invalid or not configured"
        exit 1
    fi
}

verify_organization() {
    print_section "2. Verifying AWS Organization"

    if aws organizations describe-organization &> /dev/null; then
        local org_id=$(aws organizations describe-organization --query 'Organization.Id' --output text)
        local org_arn=$(aws organizations describe-organization --query 'Organization.Arn' --output text)
        local feature_set=$(aws organizations describe-organization --query 'Organization.FeatureSet' --output text)
        local master_id=$(aws organizations describe-organization --query 'Organization.MasterAccountId' --output text)
        local master_email=$(aws organizations describe-organization --query 'Organization.MasterAccountEmail' --output text)

        check_pass "Organization exists"
        check_info "Organization ID: $org_id"
        check_info "Master Account ID: $master_id"
        check_info "Master Email: $master_email"
        check_info "Feature Set: $feature_set"

        if [[ "$feature_set" == "ALL" ]]; then
            check_pass "All features enabled (SCPs, tag policies, backup policies)"
        else
            check_warn "Organization only has consolidated billing. Enable all features for full governance."
        fi

        # Check if current account is the management account
        if [[ "$MANAGEMENT_ACCOUNT_ID" == "$master_id" ]]; then
            check_pass "Running from Management Account"
        else
            check_warn "Not running from Management Account (current: $MANAGEMENT_ACCOUNT_ID, management: $master_id)"
        fi
    else
        check_fail "No organization found or insufficient permissions"
        return 1
    fi
}

verify_accounts() {
    print_section "3. Verifying Core Accounts"

    local accounts=$(aws organizations list-accounts --output json)
    local account_count=$(echo "$accounts" | jq '.Accounts | length')

    check_info "Total accounts in organization: $account_count"

    # Store all account names for later use
    while IFS= read -r line; do
        local acc_id=$(echo "$line" | jq -r '.Id')
        local acc_name=$(echo "$line" | jq -r '.Name')
        ACCOUNT_NAMES["$acc_id"]="$acc_name"
    done < <(echo "$accounts" | jq -c '.Accounts[]')

    # List all accounts with status
    echo "" | tee -a "$LOG_FILE"
    check_info "Account Inventory:"
    echo "$accounts" | jq -r '.Accounts[] | "\(.Id) - \(.Name) - \(.Status)"' | while read -r line; do
        check_info "  $line"
    done

    # Check for Log Archive account
    local log_archive=$(echo "$accounts" | jq -r '.Accounts[] | select(.Name | test("Log.*Archive|Logging"; "i")) | .Id' | head -1)
    if [[ -n "$log_archive" ]]; then
        local log_name=$(echo "$accounts" | jq -r ".Accounts[] | select(.Id==\"$log_archive\") | .Name")
        check_pass "Log Archive account exists: $log_name (ID: $log_archive)"

        local status=$(echo "$accounts" | jq -r ".Accounts[] | select(.Id==\"$log_archive\") | .Status")
        if [[ "$status" == "ACTIVE" ]]; then
            check_pass "Log Archive account is ACTIVE"
        else
            check_warn "Log Archive account status: $status"
        fi
    else
        check_fail "Log Archive account not found"
    fi

    # Check for Security/Audit account
    local security=$(echo "$accounts" | jq -r '.Accounts[] | select(.Name | test("Security|Audit"; "i")) | .Id' | head -1)
    if [[ -n "$security" ]]; then
        local sec_name=$(echo "$accounts" | jq -r ".Accounts[] | select(.Id==\"$security\") | .Name")
        check_pass "Security/Audit account exists: $sec_name (ID: $security)"

        local status=$(echo "$accounts" | jq -r ".Accounts[] | select(.Id==\"$security\") | .Status")
        if [[ "$status" == "ACTIVE" ]]; then
            check_pass "Security/Audit account is ACTIVE"
        else
            check_warn "Security/Audit account status: $status"
        fi
    else
        check_warn "Security/Audit account not found (recommended for security services)"
    fi

    # Check for Shared Services account
    local shared=$(echo "$accounts" | jq -r '.Accounts[] | select(.Name | test("Shared.*Service|SharedServices"; "i")) | .Id' | head -1)
    if [[ -n "$shared" ]]; then
        local shared_name=$(echo "$accounts" | jq -r ".Accounts[] | select(.Id==\"$shared\") | .Name")
        check_pass "Shared Services account exists: $shared_name (ID: $shared)"
    else
        check_warn "Shared Services account not found (optional for initial setup)"
    fi
}

verify_organizational_units() {
    print_section "4. Verifying Organizational Units"

    local root_id=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
    check_info "Root ID: $root_id"

    local ous=$(aws organizations list-organizational-units-for-parent --parent-id "$root_id" --output json)
    local ou_count=$(echo "$ous" | jq '.OrganizationalUnits | length')

    check_info "Total OUs under root: $ou_count"

    # List all OUs
    echo "" | tee -a "$LOG_FILE"
    check_info "OU Structure:"
    echo "$ous" | jq -r '.OrganizationalUnits[] | "\(.Id) - \(.Name)"' | while read -r line; do
        check_info "  $line"
    done

    # Check Security OU
    local security_ou=$(echo "$ous" | jq -r '.OrganizationalUnits[] | select(.Name | test("Security"; "i")) | .Id')
    if [[ -n "$security_ou" ]]; then
        local sec_ou_name=$(echo "$ous" | jq -r ".OrganizationalUnits[] | select(.Id==\"$security_ou\") | .Name")
        check_pass "Security OU exists: $sec_ou_name (ID: $security_ou)"

        # List accounts in Security OU
        local sec_accounts=$(aws organizations list-accounts-for-parent --parent-id "$security_ou" --query 'Accounts[].Name' --output text)
        if [[ -n "$sec_accounts" ]]; then
            check_info "  Accounts: $sec_accounts"
        fi
    else
        check_warn "Security OU not found (recommended for security tooling isolation)"
    fi

    # Check Infrastructure OU
    local infra_ou=$(echo "$ous" | jq -r '.OrganizationalUnits[] | select(.Name | test("Infrastructure|Infra"; "i")) | .Id')
    if [[ -n "$infra_ou" ]]; then
        local infra_ou_name=$(echo "$ous" | jq -r ".OrganizationalUnits[] | select(.Id==\"$infra_ou\") | .Name")
        check_pass "Infrastructure OU exists: $infra_ou_name (ID: $infra_ou)"

        # List accounts in Infrastructure OU
        local infra_accounts=$(aws organizations list-accounts-for-parent --parent-id "$infra_ou" --query 'Accounts[].Name' --output text)
        if [[ -n "$infra_accounts" ]]; then
            check_info "  Accounts: $infra_accounts"
        fi
    else
        check_warn "Infrastructure OU not found"
    fi

    # Check Workloads OU
    local workloads_ou=$(echo "$ous" | jq -r '.OrganizationalUnits[] | select(.Name | test("Workload|Workloads"; "i")) | .Id')
    if [[ -n "$workloads_ou" ]]; then
        local work_ou_name=$(echo "$ous" | jq -r ".OrganizationalUnits[] | select(.Id==\"$workloads_ou\") | .Name")
        check_pass "Workloads OU exists: $work_ou_name (ID: $workloads_ou)"

        # Count workload accounts
        local work_count=$(aws organizations list-accounts-for-parent --parent-id "$workloads_ou" --query 'Accounts' --output json | jq 'length')
        check_info "  Workload accounts: $work_count"
    else
        check_warn "Workloads OU not found (optional for initial setup)"
    fi
}

verify_service_control_policies() {
    print_section "5. Verifying Service Control Policies"

    local policies=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --output json)
    local policy_count=$(echo "$policies" | jq '.Policies | length')

    check_info "Total SCPs: $policy_count"

    # List all SCPs
    echo "" | tee -a "$LOG_FILE"
    check_info "Service Control Policies:"
    echo "$policies" | jq -r '.Policies[] | "\(.Id) - \(.Name) - \(.Description // "No description")"' | while read -r line; do
        check_info "  $line"
    done

    # Check FullAWSAccess (default policy)
    local full_access=$(echo "$policies" | jq -r '.Policies[] | select(.Name=="FullAWSAccess") | .Id')
    if [[ -n "$full_access" ]]; then
        check_pass "FullAWSAccess policy exists (default policy)"
    else
        check_warn "FullAWSAccess policy not found"
    fi

    # Check for custom deny policies
    local deny_root=$(echo "$policies" | jq -r '.Policies[] | select(.Name | test("DenyRoot|Deny.*Root"; "i")) | .Id')
    if [[ -n "$deny_root" ]]; then
        local policy_name=$(echo "$policies" | jq -r ".Policies[] | select(.Id==\"$deny_root\") | .Name")
        check_pass "Root user restriction policy found: $policy_name"
    else
        check_warn "No root user restriction SCP found (recommended for security)"
    fi

    # Check for region restriction
    local region_restrict=$(echo "$policies" | jq -r '.Policies[] | select(.Name | test("Region|Geographic"; "i")) | .Id')
    if [[ -n "$region_restrict" ]]; then
        local policy_name=$(echo "$policies" | jq -r ".Policies[] | select(.Id==\"$region_restrict\") | .Name")
        check_pass "Region restriction policy found: $policy_name"
    else
        check_warn "No region restriction SCP found (consider for compliance)"
    fi

    # Verify SCP attachments
    echo "" | tee -a "$LOG_FILE"
    check_info "Checking SCP attachments to root..."
    local root_id=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
    local root_policies=$(aws organizations list-policies-for-target --target-id "$root_id" --filter SERVICE_CONTROL_POLICY --output json)
    local attached_count=$(echo "$root_policies" | jq '.Policies | length')

    if [[ $attached_count -gt 0 ]]; then
        check_pass "SCPs attached to root: $attached_count"
        echo "$root_policies" | jq -r '.Policies[] | "  - \(.Name)"' | while read -r line; do
            check_info "$line"
        done
    else
        check_warn "No SCPs attached to root (only FullAWSAccess is in effect)"
    fi
}

verify_cloudtrail() {
    print_section "6. Verifying CloudTrail Configuration"

    # Check for organization trail
    local trails=$(aws cloudtrail describe-trails --output json)
    local org_trail=$(echo "$trails" | jq -r '.trailList[] | select(.IsOrganizationTrail==true) | .Name' | head -1)

    if [[ -n "$org_trail" ]]; then
        check_pass "Organization trail exists: $org_trail"

        # Check trail status
        local status=$(aws cloudtrail get-trail-status --name "$org_trail" --output json 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            local is_logging=$(echo "$status" | jq -r '.IsLogging')

            if [[ "$is_logging" == "true" ]]; then
                check_pass "Organization trail is actively logging"

                # Get latest log time
                local latest_log=$(echo "$status" | jq -r '.LatestDeliveryTime // "N/A"')
                if [[ "$latest_log" != "N/A" ]]; then
                    check_info "  Latest log delivery: $latest_log"
                fi
            else
                check_fail "Organization trail is NOT logging"
            fi
        fi

        # Check trail configuration
        local trail_config=$(aws cloudtrail get-trail --name "$org_trail" --output json 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            local is_multiregion=$(echo "$trail_config" | jq -r '.Trail.IsMultiRegionTrail')
            local is_org_trail=$(echo "$trail_config" | jq -r '.Trail.IsOrganizationTrail')
            local log_validation=$(echo "$trail_config" | jq -r '.Trail.LogFileValidationEnabled')
            local s3_bucket=$(echo "$trail_config" | jq -r '.Trail.S3BucketName')
            local kms_key=$(echo "$trail_config" | jq -r '.Trail.KmsKeyId // "Not configured"')

            if [[ "$is_multiregion" == "true" ]]; then
                check_pass "Multi-region trail enabled"
            else
                check_warn "Multi-region trail not enabled"
            fi

            if [[ "$is_org_trail" == "true" ]]; then
                check_pass "Organization-wide trail confirmed"
            else
                check_warn "Not configured as organization trail"
            fi

            if [[ "$log_validation" == "true" ]]; then
                check_pass "Log file validation enabled"
            else
                check_warn "Log file validation not enabled (recommended for integrity)"
            fi

            check_info "  S3 Bucket: $s3_bucket"
            check_info "  KMS Key: $kms_key"
        fi

    else
        check_fail "Organization trail not found"
    fi

    # Check S3 bucket
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    local bucket_patterns=(
        "cloudtrail-logs-${account_id}"
        "aws-cloudtrail-logs-${account_id}"
        "genomic-cloudtrail-${account_id}"
    )

    local bucket_found=false
    for bucket_name in "${bucket_patterns[@]}"; do
        if aws s3 ls "s3://$bucket_name" &> /dev/null; then
            check_pass "CloudTrail S3 bucket exists: $bucket_name"
            bucket_found=true

            # Check bucket versioning
            local versioning=$(aws s3api get-bucket-versioning --bucket "$bucket_name" --output json 2>/dev/null)
            if [[ $? -eq 0 ]]; then
                local status=$(echo "$versioning" | jq -r '.Status // "Suspended"')
                if [[ "$status" == "Enabled" ]]; then
                    check_pass "  S3 bucket versioning enabled"
                else
                    check_warn "  S3 bucket versioning not enabled"
                fi
            fi

            # Check bucket encryption
            if aws s3api get-bucket-encryption --bucket "$bucket_name" &> /dev/null 2>&1; then
                check_pass "  S3 bucket encryption enabled"
            else
                check_warn "  S3 bucket encryption not configured"
            fi

            # Check bucket lifecycle
            if aws s3api get-bucket-lifecycle-configuration --bucket "$bucket_name" &> /dev/null 2>&1; then
                check_pass "  S3 bucket lifecycle policy configured"
            else
                check_warn "  S3 bucket lifecycle policy not configured (consider for cost optimization)"
            fi

            break
        fi
    done

    if [[ "$bucket_found" == false ]]; then
        check_fail "CloudTrail S3 bucket not found"
    fi
}

verify_aws_services() {
    print_section "7. Verifying AWS Service Integrations"

    local services=$(aws organizations list-aws-service-access-for-organization --output json 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        check_fail "Cannot list AWS service integrations - insufficient permissions"
        return 1
    fi

    local service_count=$(echo "$services" | jq '.EnabledServicePrincipals | length')
    check_info "Enabled service integrations: $service_count"

    # Essential services
    declare -A required_services=(
        ["cloudtrail.amazonaws.com"]="CloudTrail"
        ["config.amazonaws.com"]="AWS Config"
        ["sso.amazonaws.com"]="IAM Identity Center (SSO)"
    )

    # Recommended services
    declare -A recommended_services=(
        ["guardduty.amazonaws.com"]="GuardDuty"
        ["securityhub.amazonaws.com"]="Security Hub"
        ["access-analyzer.amazonaws.com"]="IAM Access Analyzer"
        ["backup.amazonaws.com"]="AWS Backup"
        ["compute-optimizer.amazonaws.com"]="Compute Optimizer"
    )

    echo "" | tee -a "$LOG_FILE"
    check_info "Essential Services:"
    for principal in "${!required_services[@]}"; do
        local service_name="${required_services[$principal]}"
        local enabled=$(echo "$services" | jq -r ".EnabledServicePrincipals[] | select(.ServicePrincipal==\"$principal\") | .ServicePrincipal")

        if [[ -n "$enabled" ]]; then
            local date=$(echo "$services" | jq -r ".EnabledServicePrincipals[] | select(.ServicePrincipal==\"$principal\") | .DateEnabled")
            check_pass "  $service_name enabled (since: ${date%%T*})"
        else
            check_warn "  $service_name NOT enabled (recommended for governance)"
        fi
    done

    echo "" | tee -a "$LOG_FILE"
    check_info "Recommended Services:"
    for principal in "${!recommended_services[@]}"; do
        local service_name="${recommended_services[$principal]}"
        local enabled=$(echo "$services" | jq -r ".EnabledServicePrincipals[] | select(.ServicePrincipal==\"$principal\") | .ServicePrincipal")

        if [[ -n "$enabled" ]]; then
            check_pass "  $service_name enabled"
        else
            check_info "  $service_name not enabled (optional)"
        fi
    done
}

verify_cross_account_access() {
    print_section "8. Verifying Cross-Account Access & Trust Policies"

    check_info "Testing cross-account role assumption capabilities..."
    echo "" | tee -a "$LOG_FILE"

    local accounts=$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE` && Id!=`'$MANAGEMENT_ACCOUNT_ID'`]' --output json)
    local account_count=$(echo "$accounts" | jq 'length')

    if [[ $account_count -eq 0 ]]; then
        check_warn "No member accounts found to test"
        return 0
    fi

    check_info "Testing access to $account_count member account(s)..."
    echo "" | tee -a "$LOG_FILE"

    local success_count=0
    local fail_count=0
    local trust_policy_issues=0

    # Initialize JSON report
    echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'","management_account":"'$MANAGEMENT_ACCOUNT_ID'","user":"'$CURRENT_USER_ARN'","results":[]}' > "$CROSS_ACCOUNT_REPORT"

    echo "$accounts" | jq -c '.[]' | while read -r account; do
        local account_id=$(echo "$account" | jq -r '.Id')
        local account_name=$(echo "$account" | jq -r '.Name')

        check_info "Testing: $account_name ($account_id)"

        # Try to assume OrganizationAccountAccessRole
        local role_arn="arn:aws:iam::${account_id}:role/OrganizationAccountAccessRole"
        local assume_result=$(aws sts assume-role \
            --role-arn "$role_arn" \
            --role-session-name "LandingZoneVerification-${account_id}" \
            --duration-seconds 900 \
            --output json 2>&1)

        local result_json='{"account_id":"'$account_id'","account_name":"'$account_name'","role_arn":"'$role_arn'",'

        if [[ $? -eq 0 ]]; then
            # Success - can assume role
            check_pass "  ✓ Can assume OrganizationAccountAccessRole"

            # Store credentials temporarily
            local temp_creds=$(mktemp)
            echo "$assume_result" > "$temp_creds"

            # Export temporary credentials
            export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' "$temp_creds")
            export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' "$temp_creds")
            export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' "$temp_creds")

            # Verify we can actually use the role
            local verify_identity=$(aws sts get-caller-identity --output json 2>&1)
            if [[ $? -eq 0 ]]; then
                local assumed_arn=$(echo "$verify_identity" | jq -r '.Arn')
                check_pass "  ✓ Successfully verified identity: $assumed_arn"

                # Get trust policy
                local trust_policy=$(aws iam get-role --role-name OrganizationAccountAccessRole --query 'Role.AssumeRolePolicyDocument' --output json 2>&1)
                if [[ $? -eq 0 ]]; then
                    # Check if current user is in trust policy
                    local has_mgmt_root=$(echo "$trust_policy" | jq --arg mgmt "$MANAGEMENT_ACCOUNT_ID" '.Statement[] | select(.Principal.AWS[]? | contains($mgmt + ":root"))')
                    local has_current_user=$(echo "$trust_policy" | jq --arg user "$CURRENT_USER_ARN" '.Statement[] | select(.Principal.AWS[]? | contains($user))')

                    if [[ -n "$has_mgmt_root" ]]; then
                        check_pass "  ✓ Trust policy includes management account root"
                    else
                        check_warn "  ⚠ Trust policy missing management account root"
                        ((trust_policy_issues++))
                    fi

                    if [[ -n "$has_current_user" ]] || [[ -n "$has_mgmt_root" ]]; then
                        check_pass "  ✓ Trust policy configured correctly"
                    else
                        check_warn "  ⚠ Trust policy may need updating for current user"
                    fi

                    result_json+='"status":"success","can_assume":true,"trust_policy":'$(echo "$trust_policy" | jq -c '.')
                else
                    check_warn "  ⚠ Could not retrieve trust policy"
                    result_json+='"status":"success","can_assume":true,"trust_policy_error":"Could not retrieve"'
                fi
            else
                check_warn "  ⚠ Assumed role but verification failed"
                result_json+='"status":"partial","can_assume":true,"verification_error":"'$(echo "$verify_identity" | tr -d '\n' | tr '"' "'")''"'
            fi

            # Cleanup temporary credentials
            unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
            rm -f "$temp_creds"

            ((success_count++))
            CROSS_ACCOUNT_RESULTS["$account_id"]="success"
        else
            # Failed to assume role
            local error_message=$(echo "$assume_result" | grep -oP 'error: \K.*' || echo "$assume_result")
            check_fail "  ✗ Cannot assume role"
            check_warn "  ⚠ Error: $error_message"

            # Analyze error
            if echo "$error_message" | grep -q "AccessDenied"; then
                check_warn "  → Trust policy may need configuration"
                check_warn "  → Run setup-cross-account-access.sh to fix"
            elif echo "$error_message" | grep -q "InvalidClientTokenId"; then
                check_warn "  → Credential issue detected"
            fi

            result_json+='"status":"failed","can_assume":false,"error":"'$(echo "$error_message" | tr -d '\n' | tr '"' "'")''"'
            ((fail_count++))
            CROSS_ACCOUNT_RESULTS["$account_id"]="failed"
        fi

        result_json+='}'

        # Append to JSON report
        jq --argjson new "$result_json" '.results += [$new]' "$CROSS_ACCOUNT_REPORT" > "${CROSS_ACCOUNT_REPORT}.tmp"
        mv "${CROSS_ACCOUNT_REPORT}.tmp" "$CROSS_ACCOUNT_REPORT"

        echo "" | tee -a "$LOG_FILE"
    done

    # Summary
    echo "" | tee -a "$LOG_FILE"
    check_info "Cross-Account Access Summary:"
    check_info "  Successful: $success_count accounts"
    check_info "  Failed: $fail_count accounts"
    if [[ $trust_policy_issues -gt 0 ]]; then
        check_warn "  Trust policy issues: $trust_policy_issues accounts"
    fi

    if [[ $fail_count -gt 0 ]]; then
        echo "" | tee -a "$LOG_FILE"
        check_warn "⚠ REMEDIATION REQUIRED:"
        check_warn "  Run: ./setup-cross-account-access.sh"
        check_warn "  This will configure trust policies for failed accounts"
    fi

    check_info "Detailed report: $CROSS_ACCOUNT_REPORT"
}

verify_iam_identity_center() {
    print_section "9. Verifying IAM Identity Center (AWS SSO)"

    # Check if SSO is enabled
    local sso_instances=$(aws sso-admin list-instances --output json 2>&1)

    if [[ $? -eq 0 ]]; then
        local instance_count=$(echo "$sso_instances" | jq '.Instances | length')

        if [[ $instance_count -gt 0 ]]; then
            check_pass "IAM Identity Center is configured"

            local instance_arn=$(echo "$sso_instances" | jq -r '.Instances[0].InstanceArn')
            local identity_store_id=$(echo "$sso_instances" | jq -r '.Instances[0].IdentityStoreId')

            check_info "  Instance ARN: $instance_arn"
            check_info "  Identity Store ID: $identity_store_id"

            # Check permission sets
            local permission_sets=$(aws sso-admin list-permission-sets --instance-arn "$instance_arn" --output json 2>&1)
            if [[ $? -eq 0 ]]; then
                local ps_count=$(echo "$permission_sets" | jq '.PermissionSets | length')
                check_pass "  Permission sets configured: $ps_count"

                if [[ $ps_count -eq 0 ]]; then
                    check_warn "  No permission sets found - configure for user access"
                fi
            fi

            # Check account assignments
            local accounts=$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].Id' --output json)
            local assigned_count=0

            echo "$accounts" | jq -r '.[]' | while read -r account_id; do
                local assignments=$(aws sso-admin list-account-assignments \
                    --instance-arn "$instance_arn" \
                    --account-id "$account_id" \
                    --permission-set-arn "arn:aws:sso:::permissionSet/ssoins-*/ps-*" \
                    --output json 2>/dev/null)

                if [[ $? -eq 0 ]]; then
                    local count=$(echo "$assignments" | jq '.AccountAssignments | length')
                    if [[ $count -gt 0 ]]; then
                        ((assigned_count++))
                    fi
                fi
            done

            if [[ $assigned_count -gt 0 ]]; then
                check_pass "  SSO assignments exist in $assigned_count account(s)"
            else
                check_warn "  No SSO assignments found - configure user access"
            fi
        else
            check_warn "IAM Identity Center not configured"
            check_warn "  Recommended: Enable for centralized user management"
        fi
    else
        check_warn "Cannot verify IAM Identity Center - may not be configured or insufficient permissions"
    fi
}

verify_security_posture() {
    print_section "10. Security Posture Checks"

    check_info "Analyzing security configuration..."
    echo "" | tee -a "$LOG_FILE"

    # Check if root MFA is enabled (Management Account)
    if aws iam get-account-summary &> /dev/null; then
        local summary=$(aws iam get-account-summary --output json)
        local root_mfa=$(echo "$summary" | jq -r '.SummaryMap.AccountMFAEnabled')

        if [[ "$root_mfa" == "1" ]]; then
            check_pass "Root account MFA enabled (Management Account)"
        else
            check_fail "Root account MFA NOT enabled (Management Account) - CRITICAL SECURITY ISSUE"
        fi

        # Check for IAM users (should be minimal in management account)
        local user_count=$(echo "$summary" | jq -r '.SummaryMap.Users')
        if [[ $user_count -eq 0 ]]; then
            check_pass "No IAM users in Management Account (best practice)"
        elif [[ $user_count -le 2 ]]; then
            check_warn "Few IAM users detected: $user_count (consider SSO instead)"
        else
            check_warn "Multiple IAM users detected: $user_count (migrate to SSO)"
        fi

        # Check for active access keys
        local access_keys=$(echo "$summary" | jq -r '.SummaryMap.AccountAccessKeysPresent')
        if [[ $access_keys -eq 0 ]]; then
            check_pass "No account access keys (good practice)"
        else
            check_warn "Access keys present: $access_keys (review and rotate regularly)"
        fi
    else
        check_warn "Cannot retrieve IAM account summary - insufficient permissions"
    fi

    # Check for root access keys
    local root_keys=$(aws iam list-access-keys --user-name root 2>&1)
    if [[ $? -eq 0 ]]; then
        local key_count=$(echo "$root_keys" | jq '.AccessKeyMetadata | length')
        if [[ "$key_count" == "0" ]]; then
            check_pass "No root user access keys found (Management Account)"
        else
            check_fail "Root user has $key_count access key(s) - CRITICAL SECURITY ISSUE - DELETE IMMEDIATELY"
        fi
    else
        # This is expected - root user keys query typically fails
        check_info "Cannot list root access keys (expected behavior)"
    fi

    # Check CloudTrail encryption
    local trails=$(aws cloudtrail describe-trails --output json)
    local encrypted_count=0
    local total_trails=$(echo "$trails" | jq '.trailList | length')

    echo "$trails" | jq -c '.trailList[]' | while read -r trail; do
        local kms_key=$(echo "$trail" | jq -r '.KmsKeyId // empty')
        if [[ -n "$kms_key" ]]; then
            ((encrypted_count++))
        fi
    done

    if [[ $encrypted_count -eq $total_trails ]] && [[ $total_trails -gt 0 ]]; then
        check_pass "All CloudTrail logs are encrypted"
    elif [[ $encrypted_count -gt 0 ]]; then
        check_warn "Some CloudTrail logs not encrypted ($encrypted_count/$total_trails)"
    else
        check_warn "CloudTrail logs not encrypted (consider KMS encryption)"
    fi

    echo "" | tee -a "$LOG_FILE"
    check_warn "Note: Security checks limited to Management Account"
    check_warn "Manually verify security controls in member accounts:"
    check_warn "  • Root account MFA"
    check_warn "  • No root access keys"
    check_warn "  • Password policies"
    check_warn "  • IAM Access Analyzer"
}

generate_report() {
    print_section "Verification Summary"

    local total=$((CHECKS_PASSED + CHECKS_FAILED + CHECKS_WARNING))
    local success_rate=0

    if [[ $total -gt 0 ]]; then
        success_rate=$(( (CHECKS_PASSED * 100) / total ))
    fi

    echo "" | tee -a "$LOG_FILE"
    echo -e "${GREEN}✓ Passed:   ${CHECKS_PASSED}/${total} (${success_rate}%)${NC}" | tee -a "$LOG_FILE"
    echo -e "${RED}✗ Failed:   ${CHECKS_FAILED}/${total}${NC}" | tee -a "$LOG_FILE"
    echo -e "${YELLOW}⚠ Warnings: ${CHECKS_WARNING}/${total}${NC}" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Generate comprehensive summary report
    cat > "${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt" <<EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║        AWS Landing Zone Verification Report v3.0.0            ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════
REPORT METADATA
═══════════════════════════════════════════════════════════════
Verification Date:    $(date '+%Y-%m-%d %H:%M:%S %Z')
Script Version:       ${SCRIPT_VERSION}
Management Account:   ${MANAGEMENT_ACCOUNT_ID}
Current User:         ${CURRENT_USER_ARN}
Log File:            ${LOG_FILE}

═══════════════════════════════════════════════════════════════
VERIFICATION RESULTS
═══════════════════════════════════════════════════════════════
Total Checks:         ${total}
Passed:              ${CHECKS_PASSED} (${success_rate}%)
Failed:              ${CHECKS_FAILED}
Warnings:            ${CHECKS_WARNING}

═══════════════════════════════════════════════════════════════
LANDING ZONE HEALTH ASSESSMENT
═══════════════════════════════════════════════════════════════
EOF

    # Add health assessment
    if [[ $CHECKS_FAILED -eq 0 ]] && [[ $CHECKS_WARNING -eq 0 ]]; then
        echo "Status: EXCELLENT ✓" >> "${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt"
        echo "Landing Zone is fully operational with no issues detected." >> "${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt"
    elif [[ $CHECKS_FAILED -eq 0 ]] && [[ $CHECKS_WARNING -le 5 ]]; then
        echo "Status: GOOD ✓" >> "${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt"
        echo "Landing Zone is operational with minor recommendations." >> "${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt"
    elif [[ $CHECKS_FAILED -le 2 ]]; then
        echo "Status: FAIR ⚠" >> "${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt"
        echo "Landing Zone requires attention to resolve issues." >> "${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt"
    else
        echo "Status: CRITICAL ✗" >> "${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt"
        echo "Landing Zone has critical issues requiring immediate action." >> "${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt"
    fi

    cat >> "${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt" <<EOF

═══════════════════════════════════════════════════════════════
CROSS-ACCOUNT ACCESS RESULTS
═══════════════════════════════════════════════════════════════
Detailed cross-account access report available at:
${CROSS_ACCOUNT_REPORT}

═══════════════════════════════════════════════════════════════
EOF

    echo "" | tee -a "$LOG_FILE"
    echo "Verification report saved to: ${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    if [[ $CHECKS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}✓ Landing Zone verification completed successfully!${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
        if [[ $CHECKS_WARNING -gt 0 ]]; then
            echo -e "${YELLOW}⚠ Please review ${CHECKS_WARNING} warning(s) and take recommended actions.${NC}"
        fi
    else
        echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
        echo -e "${RED}✗ Landing Zone verification found ${CHECKS_FAILED} critical issue(s).${NC}"
        echo -e "${RED}Please review and fix failed checks before proceeding.${NC}"
        echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
        return 1
    fi
}

print_recommendations() {
    print_section "Recommended Next Steps"

    echo "" | tee -a "$LOG_FILE"

    # Priority 1: Critical Security
    if [[ $CHECKS_FAILED -gt 0 ]]; then
        echo -e "${RED}PRIORITY 1 - Critical Issues:${NC}" | tee -a "$LOG_FILE"
        echo "  • Fix all failed checks immediately" | tee -a "$LOG_FILE"
        echo "  • Review security posture findings" | tee -a "$LOG_FILE"
        echo "  • Enable root account MFA if not configured" | tee -a "$LOG_FILE"
        echo "  • Delete any root access keys immediately" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
    fi

    # Priority 2: Cross-Account Access
    local failed_access=0
    for result in "${CROSS_ACCOUNT_RESULTS[@]}"; do
        if [[ "$result" == "failed" ]]; then
            ((failed_access++))
        fi
    done

    if [[ $failed_access -gt 0 ]]; then
        echo -e "${YELLOW}PRIORITY 2 - Cross-Account Access:${NC}" | tee -a "$LOG_FILE"
        echo "  • Run: ./setup-cross-account-access.sh" | tee -a "$LOG_FILE"
        echo "  • Fix trust policies for $failed_access account(s)" | tee -a "$LOG_FILE"
        echo "  • Test access after configuration" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
    fi

    # Priority 3: Governance & Compliance
    echo -e "${BLUE}PRIORITY 3 - Governance & Compliance:${NC}" | tee -a "$LOG_FILE"
    echo "  1. Enable IAM Identity Center (AWS SSO) for centralized access" | tee -a "$LOG_FILE"
    echo "  2. Configure AWS Config in all accounts" | tee -a "$LOG_FILE"
    echo "  3. Enable GuardDuty with delegated administration" | tee -a "$LOG_FILE"
    echo "  4. Set up Security Hub in Security/Audit account" | tee -a "$LOG_FILE"
    echo "  5. Review and enhance Service Control Policies" | tee -a "$LOG_FILE"
    echo "  6. Implement resource tagging strategy" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Priority 4: Operations
    echo -e "${CYAN}PRIORITY 4 - Operational Excellence:${NC}" | tee -a "$LOG_FILE"
    echo "  1. Configure billing alerts and budgets" | tee -a "$LOG_FILE"
    echo "  2. Set up CloudWatch dashboards" | tee -a "$LOG_FILE"
    echo "  3. Document emergency access procedures" | tee -a "$LOG_FILE"
    echo "  4. Create runbooks for common tasks" | tee -a "$LOG_FILE"
    echo "  5. Schedule regular compliance reviews" | tee -a "$LOG_FILE"
    echo "  6. Test disaster recovery procedures" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Additional recommendations
    echo -e "${MAGENTA}Additional Recommendations:${NC}" | tee -a "$LOG_FILE"
    echo "  • Enable CloudTrail log file validation" | tee -a "$LOG_FILE"
    echo "  • Configure CloudTrail log encryption with KMS" | tee -a "$LOG_FILE"
    echo "  • Set up S3 lifecycle policies for log archival" | tee -a "$LOG_FILE"
    echo "  • Enable IAM Access Analyzer" | tee -a "$LOG_FILE"
    echo "  • Configure AWS Backup for critical resources" | tee -a "$LOG_FILE"
    echo "  • Implement least privilege access principles" | tee -a "$LOG_FILE"
    echo "  • Enable AWS Systems Manager Session Manager" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
}

print_useful_commands() {
    print_section "Useful Commands for Landing Zone Management"

    echo "" | tee -a "$LOG_FILE"
    echo "Organization Management:" | tee -a "$LOG_FILE"
    echo "  aws organizations list-accounts" | tee -a "$LOG_FILE"
    echo "  aws organizations describe-organization" | tee -a "$LOG_FILE"
    echo "  aws organizations list-organizational-units-for-parent --parent-id <root-id>" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    echo "Cross-Account Access:" | tee -a "$LOG_FILE"
    echo "  aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/OrganizationAccountAccessRole --role-session-name test" | tee -a "$LOG_FILE"
    echo "  aws sts get-caller-identity" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    echo "Security & Compliance:" | tee -a "$LOG_FILE"
    echo "  aws cloudtrail get-trail-status --name organization-trail" | tee -a "$LOG_FILE"
    echo "  aws organizations list-policies --filter SERVICE_CONTROL_POLICY" | tee -a "$LOG_FILE"
    echo "  aws iam get-account-summary" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
}

################################################################################
# Main Execution
################################################################################

main() {
    # Start timing
    local start_time=$(date +%s)

    print_header

    echo -e "${BLUE}Starting comprehensive AWS Landing Zone verification...${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}Timestamp: $(date '+%Y-%m-%d %H:%M:%S')${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}Script Version: ${SCRIPT_VERSION}${NC}" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Run all verification checks
    verify_prerequisites
    verify_organization
    verify_accounts
    verify_organizational_units
    verify_service_control_policies
    verify_cloudtrail
    verify_aws_services
    verify_cross_account_access
    verify_iam_identity_center
    verify_security_posture

    # Generate reports and recommendations
    generate_report
    print_recommendations
    print_useful_commands

    # Calculate execution time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    echo "" | tee -a "$LOG_FILE"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}Verification completed at $(date '+%Y-%m-%d %H:%M:%S')${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}Execution time: ${minutes}m ${seconds}s${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}Log file: ${LOG_FILE}${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}Summary report: ${SUMMARY_DIR}/verification-report-${TIMESTAMP}.txt${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}Cross-account report: ${CROSS_ACCOUNT_REPORT}${NC}" | tee -a "$LOG_FILE"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Return appropriate exit code
    if [[ $CHECKS_FAILED -gt 0 ]]; then
        return 1
    else
        return 0
    fi
}

# Execute main function
main "$@"
exit $?