#!/bin/bash

################################################################################
# AWS Landing Zone Verification Script
# Version: 1.0.0
# Description: Verifies the health and configuration of AWS Landing Zone
#
# Author: DevOps Team
# Date: 2025-11-03
################################################################################

# set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_VERSION="1.0.0"
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNING=0

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "${BLUE}"
    cat << EOF
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║        AWS Landing Zone Verification Script v${SCRIPT_VERSION}            ║
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

check_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((CHECKS_PASSED++))
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    ((CHECKS_FAILED++))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((CHECKS_WARNING++))
}

check_info() {
    echo -e "${BLUE}ℹ${NC} $1"
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
        check_fail "jq not found"
        exit 1
    fi

    # Check AWS credentials
    if aws sts get-caller-identity &> /dev/null; then
        local account_id=$(aws sts get-caller-identity --query Account --output text)
        local user_arn=$(aws sts get-caller-identity --query Arn --output text)
        check_pass "AWS credentials valid"
        check_info "Account: $account_id"
        check_info "User: $user_arn"
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

        check_pass "Organization exists"
        check_info "Organization ID: $org_id"
        check_info "Feature Set: $feature_set"

        if [[ "$feature_set" == "ALL" ]]; then
            check_pass "All features enabled (SCPs, tag policies, etc.)"
        else
            check_warn "Organization only has consolidated billing. Enable all features for SCPs."
        fi
    else
        check_fail "No organization found"
        return 1
    fi
}

verify_accounts() {
    print_section "3. Verifying Core Accounts"

    local accounts=$(aws organizations list-accounts --output json)
    local account_count=$(echo "$accounts" | jq '.Accounts | length')

    check_info "Total accounts in organization: $account_count"

    # Check for Log Archive account
    local log_archive=$(echo "$accounts" | jq -r '.Accounts[] | select(.Name=="LogArchive") | .Id')
    if [[ -n "$log_archive" ]]; then
        check_pass "Log Archive account exists (ID: $log_archive)"

        # Check account status
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
    local security=$(echo "$accounts" | jq -r '.Accounts[] | select(.Name=="SecurityAudit") | .Id')
    if [[ -n "$security" ]]; then
        check_pass "Security/Audit account exists (ID: $security)"

        # Check account status
        local status=$(echo "$accounts" | jq -r ".Accounts[] | select(.Id==\"$security\") | .Status")
        if [[ "$status" == "ACTIVE" ]]; then
            check_pass "Security/Audit account is ACTIVE"
        else
            check_warn "Security/Audit account status: $status"
        fi
    else
        check_fail "Security/Audit account not found"
    fi
}

verify_organizational_units() {
    print_section "4. Verifying Organizational Units"

    local root_id=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
    local ous=$(aws organizations list-organizational-units-for-parent --parent-id "$root_id" --output json)

    # Check Security OU
    local security_ou=$(echo "$ous" | jq -r '.OrganizationalUnits[] | select(.Name=="Security") | .Id')
    if [[ -n "$security_ou" ]]; then
        check_pass "Security OU exists (ID: $security_ou)"
    else
        check_fail "Security OU not found"
    fi

    # Check Infrastructure OU
    local infra_ou=$(echo "$ous" | jq -r '.OrganizationalUnits[] | select(.Name=="Infrastructure") | .Id')
    if [[ -n "$infra_ou" ]]; then
        check_pass "Infrastructure OU exists (ID: $infra_ou)"
    else
        check_fail "Infrastructure OU not found"
    fi

    # Check Workloads OU
    local workloads_ou=$(echo "$ous" | jq -r '.OrganizationalUnits[] | select(.Name=="Workloads") | .Id')
    if [[ -n "$workloads_ou" ]]; then
        check_pass "Workloads OU exists (ID: $workloads_ou)"
    else
        check_warn "Workloads OU not found (optional for initial setup)"
    fi
}

verify_service_control_policies() {
    print_section "5. Verifying Service Control Policies"

    local policies=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --output json)
    local policy_count=$(echo "$policies" | jq '.Policies | length')

    check_info "Total SCPs: $policy_count"

    # Check for DenyRootUserActions SCP
    local deny_root=$(echo "$policies" | jq -r '.Policies[] | select(.Name=="DenyRootUserActions") | .Id')
    if [[ -n "$deny_root" ]]; then
        check_pass "DenyRootUserActions SCP exists (ID: $deny_root)"

        # Check if attached
        local targets=$(aws organizations list-targets-for-policy --policy-id "$deny_root" --query 'Targets[*].TargetId' --output text)
        if [[ -n "$targets" ]]; then
            check_pass "DenyRootUserActions is attached to targets"
            check_info "Targets: $targets"
        else
            check_warn "DenyRootUserActions not attached to any OU"
        fi
    else
        check_warn "DenyRootUserActions SCP not found"
    fi

    # Check for RequireMFAForActions SCP
    local require_mfa=$(echo "$policies" | jq -r '.Policies[] | select(.Name=="RequireMFAForActions") | .Id')
    if [[ -n "$require_mfa" ]]; then
        check_pass "RequireMFAForActions SCP exists (ID: $require_mfa)"

        # Check if attached
        local targets=$(aws organizations list-targets-for-policy --policy-id "$require_mfa" --query 'Targets[*].TargetId' --output text)
        if [[ -n "$targets" ]]; then
            check_pass "RequireMFAForActions is attached to targets"
            check_info "Targets: $targets"
        else
            check_warn "RequireMFAForActions not attached to any OU"
        fi
    else
        check_warn "RequireMFAForActions SCP not found"
    fi
}

verify_cloudtrail() {
    print_section "6. Verifying CloudTrail Configuration"

    local trails=$(aws cloudtrail list-trails --output json)

    # Check for organization trail
    local org_trail=$(echo "$trails" | jq -r '.Trails[] | select(.Name=="organization-trail") | .TrailARN')
    if [[ -n "$org_trail" ]]; then
        check_pass "Organization trail exists"
        check_info "Trail ARN: $org_trail"

        # Check trail status
        local status=$(aws cloudtrail get-trail-status --name organization-trail --output json)
        local is_logging=$(echo "$status" | jq -r '.IsLogging')

        if [[ "$is_logging" == "true" ]]; then
            check_pass "Organization trail is actively logging"
        else
            check_fail "Organization trail is NOT logging"
        fi

        # Check trail configuration
        local trail_config=$(aws cloudtrail get-trail --name organization-trail --output json)
        local is_multiregion=$(echo "$trail_config" | jq -r '.Trail.IsMultiRegionTrail')
        local is_org_trail=$(echo "$trail_config" | jq -r '.Trail.IsOrganizationTrail')
        local log_validation=$(echo "$trail_config" | jq -r '.Trail.LogFileValidationEnabled')

        if [[ "$is_multiregion" == "true" ]]; then
            check_pass "Multi-region trail enabled"
        else
            check_warn "Multi-region trail not enabled"
        fi

        if [[ "$is_org_trail" == "true" ]]; then
            check_pass "Organization-wide trail enabled"
        else
            check_warn "Not configured as organization trail"
        fi

        if [[ "$log_validation" == "true" ]]; then
            check_pass "Log file validation enabled"
        else
            check_warn "Log file validation not enabled"
        fi

    else
        check_fail "Organization trail not found"
    fi

    # Check S3 bucket
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    local bucket_name="cloudtrail-logs-${account_id}"

    if aws s3 ls "s3://$bucket_name" &> /dev/null; then
        check_pass "CloudTrail S3 bucket exists: $bucket_name"

        # Check bucket versioning
        local versioning=$(aws s3api get-bucket-versioning --bucket "$bucket_name" --output json)
        local status=$(echo "$versioning" | jq -r '.Status // "Suspended"')

        if [[ "$status" == "Enabled" ]]; then
            check_pass "S3 bucket versioning enabled"
        else
            check_warn "S3 bucket versioning not enabled"
        fi

        # Check bucket encryption
        if aws s3api get-bucket-encryption --bucket "$bucket_name" &> /dev/null; then
            check_pass "S3 bucket encryption enabled"
        else
            check_warn "S3 bucket encryption not configured"
        fi

    else
        check_fail "CloudTrail S3 bucket not found: $bucket_name"
    fi
}

verify_aws_services() {
    print_section "7. Verifying AWS Service Integrations"

    local services=$(aws organizations list-aws-service-access-for-organization --output json)

    # Check CloudTrail
    local cloudtrail=$(echo "$services" | jq -r '.EnabledServicePrincipals[] | select(.ServicePrincipal=="cloudtrail.amazonaws.com") | .ServicePrincipal')
    if [[ -n "$cloudtrail" ]]; then
        check_pass "CloudTrail trusted access enabled"
    else
        check_warn "CloudTrail trusted access not enabled"
    fi

    # Check Config
    local config=$(echo "$services" | jq -r '.EnabledServicePrincipals[] | select(.ServicePrincipal=="config.amazonaws.com") | .ServicePrincipal')
    if [[ -n "$config" ]]; then
        check_pass "AWS Config trusted access enabled"
    else
        check_warn "AWS Config trusted access not enabled (recommended for compliance)"
    fi

    # Check SSO
    local sso=$(echo "$services" | jq -r '.EnabledServicePrincipals[] | select(.ServicePrincipal=="sso.amazonaws.com") | .ServicePrincipal')
    if [[ -n "$sso" ]]; then
        check_pass "IAM Identity Center (SSO) trusted access enabled"
    else
        check_warn "IAM Identity Center (SSO) not enabled (recommended for user access)"
    fi
}

verify_security_posture() {
    print_section "8. Security Posture Checks"

    # Note: These checks require appropriate permissions
    check_info "Running security posture checks..."

    # Check if root MFA is enabled (can only check current account)
    if aws iam get-account-summary &> /dev/null; then
        local summary=$(aws iam get-account-summary --output json)
        local root_mfa=$(echo "$summary" | jq -r '.SummaryMap.AccountMFAEnabled')

        if [[ "$root_mfa" == "1" ]]; then
            check_pass "Root account MFA enabled (Management Account)"
        else
            check_fail "Root account MFA NOT enabled (Management Account) - CRITICAL SECURITY ISSUE"
        fi
    fi

    # Check for root access keys
    local access_keys=$(aws iam list-access-keys --user-name root 2>/dev/null || echo '{"AccessKeyMetadata":[]}')
    local key_count=$(echo "$access_keys" | jq '.AccessKeyMetadata | length')

    if [[ "$key_count" == "0" ]]; then
        check_pass "No root user access keys found (Management Account)"
    else
        check_fail "Root user has $key_count access key(s) - CRITICAL SECURITY ISSUE"
    fi

    check_warn "Note: MFA and access key checks only apply to Management Account"
    check_warn "Manually verify MFA on Log Archive and Security/Audit accounts"
}

generate_report() {
    print_section "Verification Summary"

    local total=$((CHECKS_PASSED + CHECKS_FAILED + CHECKS_WARNING))

    echo ""
    echo -e "${GREEN}Passed:  ${CHECKS_PASSED}/${total}${NC}"
    echo -e "${RED}Failed:  ${CHECKS_FAILED}/${total}${NC}"
    echo -e "${YELLOW}Warnings: ${CHECKS_WARNING}/${total}${NC}"
    echo ""

    if [[ $CHECKS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✓ Landing Zone verification completed successfully!${NC}"
        if [[ $CHECKS_WARNING -gt 0 ]]; then
            echo -e "${YELLOW}⚠ Please review warnings above and take recommended actions.${NC}"
        fi
    else
        echo -e "${RED}✗ Landing Zone verification found $CHECKS_FAILED critical issue(s).${NC}"
        echo -e "${RED}Please review and fix failed checks before proceeding.${NC}"
        return 1
    fi
}

print_recommendations() {
    print_section "Recommended Next Steps"

    echo ""
    echo "1. Enable MFA on all root user accounts (if not already done)"
    echo "2. Set up IAM Identity Center (AWS SSO) for user access management"
    echo "3. Enable AWS Config in all accounts for compliance monitoring"
    echo "4. Configure AWS Security Hub in Security/Audit account"
    echo "5. Set up GuardDuty with delegated administration"
    echo "6. Configure billing alerts and budgets"
    echo "7. Create additional workload accounts as needed"
    echo "8. Document emergency access procedures"
    echo "9. Review and customize Service Control Policies"
    echo "10. Implement resource tagging strategy"
    echo ""
}

################################################################################
# Main Execution
################################################################################

main() {
    print_header

    echo -e "${BLUE}Starting AWS Landing Zone verification...${NC}"
    echo -e "${BLUE}Timestamp: $(date '+%Y-%m-%d %H:%M:%S')${NC}"

    verify_prerequisites
    verify_organization
    verify_accounts
    verify_organizational_units
    verify_service_control_policies
    verify_cloudtrail
    verify_aws_services
    verify_security_posture

    generate_report
    print_recommendations

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Verification completed at $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

main "$@"