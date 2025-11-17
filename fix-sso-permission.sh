#!/bin/bash

################################################################################
# AWS SSO Permission Set Enhancement Script
# Version: 1.0.0
# Description: Adds missing DynamoDB permissions to SSO roles for Landing Zone
#              verification and management tasks
#
# Error Context:
#   User: arn:aws:sts::695094375681:assumed-role/AWSReservedSSO_AWSOrganizationsFullAccess_e7faa17da2a2ddb0/aim_binomika
#   Action: dynamodb:ListTables
#   Resource: arn:aws:dynamodb:ap-southeast-3:695094375681:table/*
#   Issue: No identity-based policy allows the action
#
# Author: DevOps Team
# Date: 2025-11-17
################################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_VERSION="1.0.0"

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  AWS SSO Permission Set Enhancement v${SCRIPT_VERSION}${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

################################################################################
# Problem Analysis
################################################################################

echo -e "${CYAN}📋 Problem Analysis${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Current Situation:${NC}"
echo "  Account ID: 695094375681"
echo "  SSO Role: AWSReservedSSO_AWSOrganizationsFullAccess_..."
echo "  User: aim_binomika"
echo "  Region: ap-southeast-3"
echo ""
echo -e "${RED}Missing Permissions:${NC}"
echo "  • dynamodb:ListTables"
echo "  • dynamodb:DescribeTable"
echo "  • dynamodb:Scan"
echo "  • dynamodb:Query"
echo ""
echo -e "${YELLOW}Why This Happens:${NC}"
echo "  The 'AWSOrganizationsFullAccess' permission set only grants"
echo "  AWS Organizations permissions. It doesn't include permissions"
echo "  for other services like DynamoDB that the landing zone uses."
echo ""

################################################################################
# Solution Options
################################################################################

echo -e "${CYAN}💡 Solution Options${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

cat << 'EOF'
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  OPTION 1: Create a New Custom Permission Set                   │
│                                                                 │
│  Create: "LandingZoneAdministrator"                             │
│  Includes:                                                      │
│    • AWS Organizations Full Access                              │
│    • DynamoDB Read Access                                       │
│    • CloudTrail Read Access                                     │
│    • CloudWatch Logs Read Access                                │
│    • IAM Read Access (for verification)                         │
│                                                                 │
│  Pros: Clean, organized, principle of least privilege           │
│  Cons: Requires SSO admin access to create                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  OPTION 2: Assign Additional Permission Set                     │
│                                                                 │
│  Assign: "ReadOnlyAccess" (AWS Managed)                         │
│  To: Your user in this account                                  │
│                                                                 │
│  Pros: Quick, uses existing AWS managed policy                  │
│  Cons: Gives more permissions than needed                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  OPTION 3: Create Inline Policy (TEMPORARY WORKAROUND)          │
│                                                                 │
│  Attach inline policy to the SSO role with DynamoDB permissions │
│                                                                 │
│  Pros: Immediate fix                                            │
│  Cons: Inline policies on SSO roles not recommended             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
EOF

echo ""
read -p "Which option would you like to implement? (1/2/3 or 'skip'): " OPTION

################################################################################
# Option 1: Create Custom Permission Set
################################################################################

if [[ "$OPTION" == "1" ]]; then
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Option 1: Creating Custom Permission Set${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    echo -e "${YELLOW}⚠️  This requires IAM Identity Center (SSO) admin access${NC}"
    echo ""

    # Get SSO instance
    echo "Detecting IAM Identity Center instance..."
    SSO_INSTANCE=$(aws sso-admin list-instances --query 'Instances[0]' --output json 2>/dev/null)

    if [[ $? -eq 0 ]] && [[ -n "$SSO_INSTANCE" ]]; then
        SSO_INSTANCE_ARN=$(echo "$SSO_INSTANCE" | jq -r '.InstanceArn')
        SSO_IDENTITY_STORE=$(echo "$SSO_INSTANCE" | jq -r '.IdentityStoreId')

        echo -e "${GREEN}✓ Found SSO Instance${NC}"
        echo "  Instance ARN: $SSO_INSTANCE_ARN"
        echo "  Identity Store: $SSO_IDENTITY_STORE"
        echo ""

        # Create permission set policy
        cat > /tmp/landing-zone-admin-policy.json << 'POLICY_EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoDBReadAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "dynamodb:Scan",
        "dynamodb:Query",
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogsReadAccess",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailReadAccess",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMReadAccess",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3ReadAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetBucketVersioning",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:ListBucket"
      ],
      "Resource": "*"
    }
  ]
}
POLICY_EOF

        echo "Creating Permission Set: LandingZoneAdministrator..."

        # Create permission set
        PERM_SET=$(aws sso-admin create-permission-set \
            --instance-arn "$SSO_INSTANCE_ARN" \
            --name "LandingZoneAdministrator" \
            --description "Full access to AWS Organizations plus read access to resources needed for landing zone management" \
            --session-duration "PT8H" \
            --output json 2>/dev/null)

        if [[ $? -eq 0 ]]; then
            PERM_SET_ARN=$(echo "$PERM_SET" | jq -r '.PermissionSet.PermissionSetArn')
            echo -e "${GREEN}✓ Permission Set Created${NC}"
            echo "  ARN: $PERM_SET_ARN"
            echo ""

            # Attach AWS managed policy for Organizations
            echo "Attaching AWSOrganizationsFullAccess..."
            aws sso-admin attach-managed-policy-to-permission-set \
                --instance-arn "$SSO_INSTANCE_ARN" \
                --permission-set-arn "$PERM_SET_ARN" \
                --managed-policy-arn "arn:aws:iam::aws:policy/AWSOrganizationsFullAccess"

            echo -e "${GREEN}✓ Attached AWSOrganizationsFullAccess${NC}"
            echo ""

            # Attach custom inline policy
            echo "Attaching custom policy for additional services..."
            aws sso-admin put-inline-policy-to-permission-set \
                --instance-arn "$SSO_INSTANCE_ARN" \
                --permission-set-arn "$PERM_SET_ARN" \
                --inline-policy file:///tmp/landing-zone-admin-policy.json

            echo -e "${GREEN}✓ Attached custom inline policy${NC}"
            echo ""

            echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}✓ Permission Set Created Successfully!${NC}"
            echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${YELLOW}Next Steps:${NC}"
            echo "  1. Go to IAM Identity Center console"
            echo "  2. Navigate to: AWS accounts → Your account (695094375681)"
            echo "  3. Assign the 'LandingZoneAdministrator' permission set to your user"
            echo "  4. Log out and log back in to SSO"
            echo "  5. Re-run the verification script"
            echo ""

        else
            echo -e "${RED}✗ Failed to create permission set${NC}"
            echo "You may not have sufficient permissions or the permission set may already exist."
        fi
    else
        echo -e "${RED}✗ Cannot detect IAM Identity Center instance${NC}"
        echo "You may need to run this from the management account or with appropriate permissions."
    fi

################################################################################
# Option 2: Assign ReadOnlyAccess
################################################################################

elif [[ "$OPTION" == "2" ]]; then
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Option 2: Assigning ReadOnlyAccess Permission Set${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    echo -e "${YELLOW}Manual Steps Required:${NC}"
    echo ""
    echo "1. Open AWS IAM Identity Center console"
    echo "   https://console.aws.amazon.com/singlesignon"
    echo ""
    echo "2. Navigate to: AWS accounts → Select account 695094375681"
    echo ""
    echo "3. Click 'Assign users or groups'"
    echo ""
    echo "4. Select your user: aim_binomika"
    echo ""
    echo "5. Select permission set: ReadOnlyAccess (AWS Managed)"
    echo ""
    echo "6. Click 'Submit'"
    echo ""
    echo "7. Log out from AWS SSO and log back in"
    echo ""
    echo "8. Re-run the verification script"
    echo ""

################################################################################
# Option 3: Inline Policy (Not Recommended)
################################################################################

elif [[ "$OPTION" == "3" ]]; then
    echo ""
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  Option 3: Creating Inline Policy (Temporary Workaround)${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo ""

    echo -e "${RED}⚠️  WARNING: Inline policies on SSO roles are not recommended!${NC}"
    echo -e "${RED}    This is a temporary workaround only.${NC}"
    echo ""

    read -p "Are you sure you want to proceed? (yes/no): " CONFIRM

    if [[ "$CONFIRM" == "yes" ]]; then
        ROLE_NAME="AWSReservedSSO_AWSOrganizationsFullAccess_e7faa17da2a2ddb0"

        cat > /tmp/dynamodb-read-policy.json << 'POLICY_EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoDBReadAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "dynamodb:Scan",
        "dynamodb:Query",
        "dynamodb:GetItem"
      ],
      "Resource": "*"
    }
  ]
}
POLICY_EOF

        echo "Attempting to attach inline policy..."
        aws iam put-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-name "TempDynamoDBReadAccess" \
            --policy-document file:///tmp/dynamodb-read-policy.json 2>&1

        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}✓ Policy attached successfully${NC}"
            echo ""
            echo -e "${YELLOW}Note: This is temporary and may be overwritten by SSO${NC}"
            echo "Please implement Option 1 or 2 for a permanent solution."
        else
            echo -e "${RED}✗ Failed to attach policy${NC}"
            echo "SSO roles are typically managed by IAM Identity Center."
            echo "Please use Option 1 or 2 instead."
        fi
    else
        echo "Cancelled."
    fi

else
    echo ""
    echo "Skipped. Please choose an option and re-run this script."
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Additional Information${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

cat << 'EOF'
📚 Understanding SSO Permissions

SSO Permission Sets are templates that define what AWS services and
resources users can access. They are:

  • Managed centrally in IAM Identity Center
  • Assigned to users/groups for specific accounts
  • Can include AWS managed policies + custom policies
  • Apply immediately but require re-authentication

Why Your Current Role Lacks DynamoDB Access:

  The "AWSOrganizationsFullAccess" permission set includes:
    ✓ AWS Organizations actions (create accounts, OUs, policies)
    ✗ DynamoDB access (not included)
    ✗ CloudWatch Logs access (not included)
    ✗ Other service access (not included by default)

For Landing Zone Management, You Need:

  • AWS Organizations (already have)
  • DynamoDB - for configuration tables
  • CloudWatch Logs - for audit trails
  • CloudTrail - for compliance verification
  • IAM - for role and policy verification
  • S3 - for log bucket access

EOF

echo -e "${CYAN}🔗 Helpful Links${NC}"
echo ""
echo "IAM Identity Center Console:"
echo "  https://console.aws.amazon.com/singlesignon"
echo ""
echo "Permission Sets Documentation:"
echo "  https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsets.html"
echo ""
echo "AWS Managed Policies:"
echo "  https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html"
echo ""

echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Done!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""