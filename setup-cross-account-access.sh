#!/bin/bash

# Setup Cross-Account Access for Post-Deployment Automation
# This script configures OrganizationAccountAccessRole trust policies

set -e

MANAGEMENT_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
LOG_ARCHIVE_ACCOUNT_ID="204898220138"
SECURITY_AUDIT_ACCOUNT_ID="049749093828"

echo "Management Account: $MANAGEMENT_ACCOUNT_ID"
echo ""
echo "This script will update trust policies for OrganizationAccountAccessRole"
echo "in Log Archive and Security/Audit accounts to allow access from:"
echo "  - Management account root"
echo "  - IAM user: devsecops-binomika"
echo ""
read -p "Continue? (yes/no): " confirm
[[ "$confirm" != "yes" ]] && exit 0

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
        "AWS": [
          "arn:aws:iam::${MANAGEMENT_ACCOUNT_ID}:root",
          "arn:aws:iam::${MANAGEMENT_ACCOUNT_ID}:user/devsecops-binomika"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# Update Log Archive account
echo "Updating Log Archive account ($LOG_ARCHIVE_ACCOUNT_ID)..."
create_trust_policy $LOG_ARCHIVE_ACCOUNT_ID
aws iam update-assume-role-policy \
    --role-name OrganizationAccountAccessRole \
    --policy-document file:///tmp/trust-policy-${LOG_ARCHIVE_ACCOUNT_ID}.json \
    --profile log-archive 2>/dev/null || echo "Failed - ensure AWS profile 'log-archive' exists"

# Update Security/Audit account
echo "Updating Security/Audit account ($SECURITY_AUDIT_ACCOUNT_ID)..."
create_trust_policy $SECURITY_AUDIT_ACCOUNT_ID
aws iam update-assume-role-policy \
    --role-name OrganizationAccountAccessRole \
    --policy-document file:///tmp/trust-policy-${SECURITY_AUDIT_ACCOUNT_ID}.json \
    --profile security-audit 2>/dev/null || echo "Failed - ensure AWS profile 'security-audit' exists"

echo ""
echo "Done! Trust policies updated."
echo ""
echo "To test access, run:"
echo "  aws sts assume-role --role-arn arn:aws:iam::${LOG_ARCHIVE_ACCOUNT_ID}:role/OrganizationAccountAccessRole --role-session-name test"
