#!/bin/bash

################################################################################
# AWS Cross-Account Access Setup Script
# Version: 2.0.0
# Description: Configures OrganizationAccountAccessRole trust policies to allow
#              access from management account root AND federated SSO users
#
# This script addresses the circular permission issue where:
# - SSO federated users need to assume roles across accounts
# - OrganizationAccountAccessRole needs proper trust policies
# - Admin access is required to update these trust policies
#
# Author: DevOps Team
# Date: 2025-11-17
################################################################################

# set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_VERSION="3.0.0"

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  AWS Cross-Account Access Setup v${SCRIPT_VERSION}${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Get management account ID
MANAGEMENT_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")

if [[ -z "$MANAGEMENT_ACCOUNT_ID" ]]; then
    echo -e "${RED}Error: Cannot determine AWS account ID${NC}"
    echo -e "${RED}Please configure AWS credentials first${NC}"
    exit 1
fi

echo -e "${GREEN}Management Account ID: $MANAGEMENT_ACCOUNT_ID${NC}"
echo ""

# Get current user identity
CURRENT_USER_ARN=$(aws sts get-caller-identity --query Arn --output text)
echo -e "${GREEN}Current User: $CURRENT_USER_ARN${NC}"
echo ""

# Detect if user is federated (SSO) or IAM user
if [[ "$CURRENT_USER_ARN" == *"assumed-role"* ]]; then
    USER_TYPE="federated"
    # Extract the role name from the ARN
    ROLE_NAME=$(echo "$CURRENT_USER_ARN" | cut -d'/' -f2)
    echo -e "${YELLOW}Detected: Federated SSO user (Role: $ROLE_NAME)${NC}"
elif [[ "$CURRENT_USER_ARN" == *":user/"* ]]; then
    USER_TYPE="iam"
    USER_NAME=$(echo "$CURRENT_USER_ARN" | cut -d'/' -f2)
    echo -e "${YELLOW}Detected: IAM User ($USER_NAME)${NC}"
else
    USER_TYPE="unknown"
    echo -e "${RED}Warning: Unknown user type${NC}"
fi

echo ""
echo -e "${YELLOW}This script will update OrganizationAccountAccessRole trust policies${NC}"
echo -e "${YELLOW}in ALL member accounts to allow:${NC}"
echo -e "${YELLOW}  1. Management account root access${NC}"
echo -e "${YELLOW}  2. Current user access ($CURRENT_USER_ARN)${NC}"
echo ""

read -p "Continue? (yes/no): " confirm
if [[ "$confirm" != "yes" ]]; then
    echo "Cancelled."
    exit 0
fi

echo ""

# Function to create trust policy
create_trust_policy() {
    local account_id=$1
    local policy_file="/tmp/trust-policy-${account_id}.json"

    # Build principals array
    local principals='"arn:aws:iam::'${MANAGEMENT_ACCOUNT_ID}':root"'

    # Add current user to principals if not root
    if [[ "$USER_TYPE" == "iam" ]]; then
        principals+=', "arn:aws:iam::'${MANAGEMENT_ACCOUNT_ID}':user/'${USER_NAME}'"'
    elif [[ "$USER_TYPE" == "federated" ]]; then
        # For federated users, add the assumed role ARN
        local role_arn=$(echo "$CURRENT_USER_ARN" | cut -d'/' -f1-2)
        principals+=', "'${role_arn}'"'
    fi

    # Create trust policy JSON
    cat > "$policy_file" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          ${principals}
        ]
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
EOF

    echo "$policy_file"
}

# Get all member accounts (exclude management account)
echo -e "${BLUE}Fetching member accounts...${NC}"
ACCOUNTS=$(aws organizations list-accounts \
    --query 'Accounts[?Status==`ACTIVE` && Id!=`'$MANAGEMENT_ACCOUNT_ID'`].[Id,Name]' \
    --output json)

ACCOUNT_COUNT=$(echo "$ACCOUNTS" | jq 'length')
echo -e "${GREEN}Found $ACCOUNT_COUNT member accounts${NC}"
echo ""

# Track results
SUCCESS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Create temporary directory for credentials
TEMP_DIR="/tmp/aws-cross-account-setup-$$"
mkdir -p "$TEMP_DIR"

# Process each account
echo "$ACCOUNTS" | jq -c '.[]' | while read -r account; do
    ACCOUNT_ID=$(echo "$account" | jq -r '.[0]')
    ACCOUNT_NAME=$(echo "$account" | jq -r '.[1]')

    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}Processing: $ACCOUNT_NAME ($ACCOUNT_ID)${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Try to assume role in the account
    echo "  Attempting to assume OrganizationAccountAccessRole..."

    CREDENTIALS=$(aws sts assume-role \
        --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/OrganizationAccountAccessRole" \
        --role-session-name "TrustPolicyUpdate-${ACCOUNT_ID}" \
        --duration-seconds 3600 \
        --output json 2>&1)

    if [[ $? -ne 0 ]]; then
        echo -e "${RED}  ✗ Cannot assume role in $ACCOUNT_NAME${NC}"
        echo -e "${RED}    Reason: $(echo "$CREDENTIALS" | grep -oP '(?<=error: ).*' || echo 'Access Denied')${NC}"
        echo -e "${YELLOW}    This account needs manual trust policy configuration${NC}"
        echo ""
        ((SKIP_COUNT++))
        continue
    fi

    echo -e "${GREEN}  ✓ Successfully assumed role${NC}"

    # Save credentials to temporary file
    CRED_FILE="${TEMP_DIR}/credentials-${ACCOUNT_ID}.json"
    echo "$CREDENTIALS" > "$CRED_FILE"

    # Export temporary credentials
    export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' "$CRED_FILE")
    export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' "$CRED_FILE")
    export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' "$CRED_FILE")

    # Create trust policy
    POLICY_FILE=$(create_trust_policy "$ACCOUNT_ID")

    echo "  Updating trust policy..."

    # Update trust policy
    if aws iam update-assume-role-policy \
        --role-name OrganizationAccountAccessRole \
        --policy-document file://"$POLICY_FILE" 2>&1; then
        echo -e "${GREEN}  ✓ Trust policy updated successfully${NC}"
        ((SUCCESS_COUNT++))
    else
        echo -e "${RED}  ✗ Failed to update trust policy${NC}"
        ((FAIL_COUNT++))
    fi

    # Clean up credentials
    unset AWS_ACCESS_KEY_ID
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_SESSION_TOKEN

    rm -f "$POLICY_FILE" "$CRED_FILE"
    echo ""
done

# Cleanup
rm -rf "$TEMP_DIR"

# Summary
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Summary${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Successfully updated: $SUCCESS_COUNT accounts${NC}"
echo -e "${RED}Failed: $FAIL_COUNT accounts${NC}"
echo -e "${YELLOW}Skipped (no access): $SKIP_COUNT accounts${NC}"
echo ""

if [[ $SKIP_COUNT -gt 0 ]]; then
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}MANUAL ACTION REQUIRED${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}For accounts that were skipped, you need to:${NC}"
    echo ""
    echo -e "${YELLOW}1. Sign in to each account using root credentials${NC}"
    echo -e "${YELLOW}2. Go to IAM Console → Roles → OrganizationAccountAccessRole${NC}"
    echo -e "${YELLOW}3. Edit Trust Relationship and add:${NC}"
    echo ""
    echo -e '    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::'${MANAGEMENT_ACCOUNT_ID}':root",
          "'${CURRENT_USER_ARN}'"
        ]
      },
      "Action": "sts:AssumeRole"
    }'
    echo ""
    echo -e "${YELLOW}4. Save the updated trust policy${NC}"
    echo ""
fi

if [[ $SUCCESS_COUNT -gt 0 ]]; then
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Next Steps:${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}1. You can now run post-deployment automation scripts${NC}"
    echo -e "${GREEN}2. Test cross-account access:${NC}"
    echo -e "   ${GREEN}aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/OrganizationAccountAccessRole --role-session-name test${NC}"
    echo -e "${GREEN}3. Configure IAM Identity Center (AWS SSO) for team access${NC}"
    echo ""
fi

echo -e "${BLUE}Done!${NC}"