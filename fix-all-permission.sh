#!/bin/bash

################################################################################
# AWS Landing Zone - Complete Permission Set Creator
# Version: 2.0.0
#
# This script creates a comprehensive permission set that includes ALL
# permissions needed for AWS Landing Zone verification and management
#
# Missing Permissions Detected:
#   - dynamodb:ListTables
#   - servicecatalog:ListApplications
#   - (and likely many more)
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
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  AWS Landing Zone - Complete Permission Set Setup${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Account details
ACCOUNT_ID="695094375681"
USER_NAME="aim_binomika"
REGION="ap-southeast-3"

echo -e "${CYAN}📋 Current Situation${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Account: $ACCOUNT_ID"
echo "User: $USER_NAME"
echo "Region: $REGION"
echo "Current Role: AWSReservedSSO_AWSOrganizationsFullAccess"
echo ""
echo -e "${RED}Missing Permissions:${NC}"
echo "  ❌ dynamodb:ListTables"
echo "  ❌ servicecatalog:ListApplications"
echo "  ❌ cloudwatch:DescribeAlarms"
echo "  ❌ cloudtrail:LookupEvents"
echo "  ❌ config:DescribeConfigRules"
echo "  ❌ iam:GetAccountSummary"
echo "  ❌ s3:ListBucket"
echo "  ❌ lambda:ListFunctions"
echo "  ❌ logs:DescribeLogGroups"
echo "  ... and more"
echo ""

################################################################################
# Create Complete Permission Policy
################################################################################

echo -e "${CYAN}📝 Creating Comprehensive Permission Policy${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cat > /tmp/landing-zone-complete-policy.json << 'POLICY_EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoDBAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "dynamodb:Scan",
        "dynamodb:Query",
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem",
        "dynamodb:DescribeTimeToLive"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ServiceCatalogAccess",
      "Effect": "Allow",
      "Action": [
        "servicecatalog:ListApplications",
        "servicecatalog:DescribeProduct",
        "servicecatalog:DescribeProductView",
        "servicecatalog:ListPortfolios",
        "servicecatalog:DescribePortfolio",
        "servicecatalog:SearchProducts",
        "servicecatalog:DescribeProvisioningParameters"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchAccess",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DescribeAlarmsForMetric",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogsAccess",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
        "logs:DescribeMetricFilters"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailAccess",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:LookupEvents",
        "cloudtrail:GetInsightSelectors",
        "cloudtrail:ListTrails"
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
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListMFADevices",
        "iam:GetLoginProfile"
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
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicy",
        "s3:ListBucket",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ConfigAccess",
      "Effect": "Allow",
      "Action": [
        "config:DescribeConfigRules",
        "config:DescribeConfigurationRecorders",
        "config:DescribeDeliveryChannels",
        "config:GetComplianceDetailsByConfigRule",
        "config:DescribeComplianceByConfigRule"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LambdaReadAccess",
      "Effect": "Allow",
      "Action": [
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:ListTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2ReadAccess",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRouteTables",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SNSAccess",
      "Effect": "Allow",
      "Action": [
        "sns:ListTopics",
        "sns:GetTopicAttributes",
        "sns:ListSubscriptions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "KMSAccess",
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:ListAliases",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GuardDutyAccess",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecurityHubAccess",
      "Effect": "Allow",
      "Action": [
        "securityhub:DescribeHub",
        "securityhub:GetFindings",
        "securityhub:GetEnabledStandards"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SSOAdminReadAccess",
      "Effect": "Allow",
      "Action": [
        "sso:ListInstances",
        "sso:DescribeRegisteredRegions",
        "sso-directory:SearchUsers",
        "identitystore:ListUsers",
        "identitystore:ListGroups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ControlTowerAccess",
      "Effect": "Allow",
      "Action": [
        "controltower:GetLandingZone",
        "controltower:ListEnabledControls"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SupportAccess",
      "Effect": "Allow",
      "Action": [
        "support:DescribeTrustedAdvisorChecks",
        "support:DescribeTrustedAdvisorCheckResult"
      ],
      "Resource": "*"
    }
  ]
}
POLICY_EOF

echo -e "${GREEN}✓ Policy document created: /tmp/landing-zone-complete-policy.json${NC}"
echo ""

################################################################################
# Display the solution options
################################################################################

echo -e "${CYAN}💡 Solution Options${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cat << 'EOF'
You have 3 options to fix the permission issues:

┌─────────────────────────────────────────────────────────────────┐
│ OPTION 1: Use AWS Managed Policy (FASTEST - 2 MINUTES)         │
└─────────────────────────────────────────────────────────────────┘

Assign "ViewOnlyAccess" or "ReadOnlyAccess" permission set to your user.
This gives you read access to ALL AWS services.

Pros:
  ✓ Immediate solution
  ✓ No custom policy creation needed
  ✓ Covers all services

Cons:
  ⚠ Broader permissions than strictly needed
  ⚠ Still need Organizations full access (keep your current role)

Steps:
  1. Open IAM Identity Center console
  2. Go to AWS accounts → 695094375681
  3. Assign users → aim_binomika
  4. Select "ViewOnlyAccess" permission set
  5. Submit

┌─────────────────────────────────────────────────────────────────┐
│ OPTION 2: Create Custom Permission Set (RECOMMENDED)           │
└─────────────────────────────────────────────────────────────────┘

Create "LandingZoneAdministrator" with precise permissions.

Pros:
  ✓ Principle of least privilege
  ✓ Exactly what you need, nothing more
  ✓ Better security posture

Cons:
  ⚠ Requires IAM Identity Center admin access
  ⚠ Takes 5-10 minutes to set up

Steps:
  1. Run this script and select Option 2
  2. Follow the automated setup
  3. Assign to your user

┌─────────────────────────────────────────────────────────────────┐
│ OPTION 3: Skip Services (WORKAROUND)                           │
└─────────────────────────────────────────────────────────────────┘

Modify the verification script to skip services you can't access.

Pros:
  ✓ No permission changes needed
  ✓ Can run immediately

Cons:
  ⚠ Incomplete verification
  ⚠ May miss important issues
  ⚠ Not recommended for production

EOF

echo ""
read -p "Which option would you like? (1/2/3 or 'skip'): " OPTION

################################################################################
# Option 1: Assign ViewOnlyAccess
################################################################################

if [[ "$OPTION" == "1" ]]; then
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Option 1: Assigning ViewOnlyAccess${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    echo "Since this requires SSO console access, here are the exact steps:"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Keep your existing AWSOrganizationsFullAccess role!${NC}"
    echo "You'll have TWO permission sets assigned:"
    echo "  1. AWSOrganizationsFullAccess (for write access to Organizations)"
    echo "  2. ViewOnlyAccess (for read access to other services)"
    echo ""

    echo "📋 Manual Steps:"
    echo ""
    echo "1. Open IAM Identity Center Console:"
    echo "   https://console.aws.amazon.com/singlesignon"
    echo ""
    echo "2. Navigate to: AWS accounts"
    echo ""
    echo "3. Find and click account: 695094375681"
    echo ""
    echo "4. Click: 'Assign users or groups'"
    echo ""
    echo "5. Select user: aim_binomika"
    echo "   Click: Next"
    echo ""
    echo "6. Select permission set: ViewOnlyAccess"
    echo "   (This is an AWS managed permission set)"
    echo "   Click: Next"
    echo ""
    echo "7. Review and click: Submit"
    echo ""
    echo "8. IMPORTANT: Log out from AWS SSO completely"
    echo "   Then log back in"
    echo ""
    echo "9. When you log in, select account 695094375681"
    echo "   You should see BOTH permission sets available"
    echo ""
    echo "10. Select ViewOnlyAccess for verification tasks"
    echo ""

    echo -e "${GREEN}After completing these steps, run:${NC}"
    echo "  ./verify-landing-zone-v3.0.0.sh"
    echo ""

################################################################################
# Option 2: Create Custom Permission Set
################################################################################

elif [[ "$OPTION" == "2" ]]; then
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Option 2: Creating Custom Permission Set${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Detect SSO instance
    echo "Detecting IAM Identity Center instance..."
    SSO_INSTANCE=$(aws sso-admin list-instances --query 'Instances[0]' --output json 2>&1)

    if [[ $? -eq 0 ]] && [[ "$SSO_INSTANCE" != "null" ]]; then
        SSO_INSTANCE_ARN=$(echo "$SSO_INSTANCE" | jq -r '.InstanceArn')
        SSO_IDENTITY_STORE=$(echo "$SSO_INSTANCE" | jq -r '.IdentityStoreId')

        echo -e "${GREEN}✓ Found SSO Instance${NC}"
        echo "  Instance ARN: $SSO_INSTANCE_ARN"
        echo ""

        # Create permission set
        echo "Creating permission set: LandingZoneAdministrator..."

        PERM_SET_RESULT=$(aws sso-admin create-permission-set \
            --instance-arn "$SSO_INSTANCE_ARN" \
            --name "LandingZoneAdministrator" \
            --description "Complete access for AWS Landing Zone management and verification" \
            --session-duration "PT8H" \
            --output json 2>&1)

        if [[ $? -eq 0 ]]; then
            PERM_SET_ARN=$(echo "$PERM_SET_RESULT" | jq -r '.PermissionSet.PermissionSetArn')

            echo -e "${GREEN}✓ Permission set created${NC}"
            echo "  ARN: $PERM_SET_ARN"
            echo ""

            # Attach AWS Organizations full access
            echo "Attaching AWSOrganizationsFullAccess managed policy..."
            aws sso-admin attach-managed-policy-to-permission-set \
                --instance-arn "$SSO_INSTANCE_ARN" \
                --permission-set-arn "$PERM_SET_ARN" \
                --managed-policy-arn "arn:aws:iam::aws:policy/AWSOrganizationsFullAccess" 2>&1

            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}✓ Attached AWSOrganizationsFullAccess${NC}"
            fi
            echo ""

            # Attach custom inline policy
            echo "Attaching custom inline policy for additional services..."
            aws sso-admin put-inline-policy-to-permission-set \
                --instance-arn "$SSO_INSTANCE_ARN" \
                --permission-set-arn "$PERM_SET_ARN" \
                --inline-policy file:///tmp/landing-zone-complete-policy.json 2>&1

            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}✓ Attached custom policy${NC}"
            fi
            echo ""

            echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}✓ Permission Set Created Successfully!${NC}"
            echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
            echo ""

            echo -e "${YELLOW}Next Steps:${NC}"
            echo ""
            echo "1. Go to IAM Identity Center console:"
            echo "   https://console.aws.amazon.com/singlesignon"
            echo ""
            echo "2. Navigate to: AWS accounts → 695094375681"
            echo ""
            echo "3. Click: Assign users or groups"
            echo ""
            echo "4. Select user: aim_binomika"
            echo ""
            echo "5. Select permission set: LandingZoneAdministrator"
            echo ""
            echo "6. Click: Submit"
            echo ""
            echo "7. REMOVE the old AWSOrganizationsFullAccess assignment"
            echo "   (The new permission set includes everything)"
            echo ""
            echo "8. Log out and log back in to AWS SSO"
            echo ""
            echo "9. Run: ./verify-landing-zone-v3.0.0.sh"
            echo ""

        else
            echo -e "${RED}✗ Failed to create permission set${NC}"
            echo ""
            echo "Error details:"
            echo "$PERM_SET_RESULT"
            echo ""
            echo "Possible reasons:"
            echo "  • Permission set with that name already exists"
            echo "  • Insufficient permissions to create permission sets"
            echo "  • Need to run from management account"
            echo ""
            echo "Try Option 1 (ViewOnlyAccess) instead."
        fi
    else
        echo -e "${RED}✗ Cannot detect IAM Identity Center instance${NC}"
        echo ""
        echo "This could mean:"
        echo "  • IAM Identity Center is not enabled"
        echo "  • You don't have permissions to query SSO"
        echo "  • Need to run from the management account"
        echo ""
        echo "Please use Option 1 (ViewOnlyAccess) instead."
    fi

################################################################################
# Option 3: Skip Services
################################################################################

elif [[ "$OPTION" == "3" ]]; then
    echo ""
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  Option 3: Creating Modified Verification Script${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo ""

    echo -e "${RED}⚠️  WARNING: This will provide incomplete verification${NC}"
    echo ""

    cat > /tmp/skip_services.patch << 'PATCH_EOF'
# Add these environment variables before running the script:

export SKIP_DYNAMODB=true
export SKIP_SERVICECATALOG=true
export SKIP_LAMBDA=true
export SKIP_CONFIG=true

# Then run:
./verify-landing-zone-v3.0.0.sh
PATCH_EOF

    echo "A workaround has been saved to: /tmp/skip_services.patch"
    echo ""
    echo "However, we STRONGLY recommend using Option 1 or 2 instead."
    echo ""

else
    echo ""
    echo "No option selected. Please re-run and choose an option."
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Summary of All Required Permissions${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

cat << 'EOF'
The verification script needs read access to these services:

✓ AWS Organizations    - Account and OU management
✓ DynamoDB             - Configuration tables
✓ Service Catalog      - Product and portfolio info
✓ CloudWatch           - Alarms and metrics
✓ CloudWatch Logs      - Log groups and streams
✓ CloudTrail           - Audit trails
✓ IAM                  - Roles, policies, users
✓ S3                   - Buckets and objects
✓ Config               - Compliance rules
✓ Lambda               - Functions
✓ EC2/VPC              - Network configuration
✓ SNS                  - Topics and subscriptions
✓ KMS                  - Encryption keys
✓ GuardDuty            - Security findings
✓ Security Hub         - Security posture
✓ IAM Identity Center  - SSO configuration
✓ Control Tower        - Landing Zone status

All of these are READ-ONLY operations!

EOF

echo -e "${GREEN}Done!${NC}"
echo ""