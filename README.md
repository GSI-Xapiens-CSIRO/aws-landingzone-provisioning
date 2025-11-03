# AWS Landing Zone Provisioning Script

## Overview

This bash script automates the provisioning of a foundational AWS Landing Zone following AWS best practices and Control Tower concepts. It creates a multi-account AWS environment with proper organizational structure, security controls, and governance.

## Architecture

```
AWS Organization (Root)
├── Management Account (existing)
│   ├── AWS Organizations
│   ├── Consolidated Billing
│   └── Organization CloudTrail
│
├── Security OU
│   └── SecurityAudit Account
│       ├── AWS Config
│       ├── Security Hub
│       ├── GuardDuty (delegated admin)
│       └── IAM Access Analyzer
│
├── Infrastructure OU
│   └── LogArchive Account
│       ├── Centralized logging
│       ├── CloudTrail logs
│       └── Immutable log storage
│
└── Workloads OU
    └── (Future workload accounts)
```

## Features

✓ **AWS Organizations Setup**
  - Creates organization with all features enabled
  - Establishes hierarchical OU structure
  - Implements consolidated billing

✓ **Core Account Provisioning**
  - Log Archive Account for centralized logging
  - Security/Audit Account for security tooling
  - Automated account creation and organization

✓ **Service Control Policies (SCPs)**
  - DenyRootUserActions - Prevents root user access
  - RequireMFAForActions - Enforces MFA for sensitive operations
  - Automated SCP attachment to OUs

✓ **CloudTrail Organization Trail**
  - Multi-region logging
  - Log file validation
  - Centralized S3 storage with encryption

✓ **Security Best Practices**
  - Least-privilege access patterns
  - Defense-in-depth architecture
  - Separation of duties through account isolation

## Prerequisites

### Required Tools
- **AWS CLI** version 2.x or later
- **jq** (JSON processor)
- **bash** version 4.x or later

### AWS Permissions
The script must be run from an AWS account with the following permissions:
- `organizations:*` (AWS Organizations full access)
- `iam:*` (IAM full access for SCP management)
- `cloudtrail:*` (CloudTrail management)
- `s3:*` (S3 bucket creation and management)
- `sts:GetCallerIdentity` (Identity verification)

### Account Requirements
- Must be run from the **Management Account** (root account of organization)
- Management account must NOT already be part of an organization
- Root user access or equivalent administrative permissions required

## Installation

1. **Download the script:**
```bash
curl -O https://your-repo/provision-aws-landing-zone.sh
chmod +x provision-aws-landing-zone.sh
```

2. **Install dependencies:**
```bash
# Install AWS CLI (if not already installed)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Install jq
sudo apt-get install jq  # Debian/Ubuntu
sudo yum install jq      # RHEL/CentOS
brew install jq          # macOS
```

3. **Configure AWS credentials:**
```bash
aws configure
# OR
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="ap-southeast-3"
```

## Configuration

### Environment Variables

**Required:**
```bash
export LOG_ARCHIVE_EMAIL="aws-log-archive@yourdomain.com"
export SECURITY_AUDIT_EMAIL="aws-security-audit@yourdomain.com"
```

**Optional:**
```bash
export ORG_NAME="MyOrganization"                    # Default: MyOrganization
export AWS_REGION="ap-southeast-3"                   # Default: ap-southeast-3
```

### Email Requirements
- Each account requires a **unique** email address
- Email addresses must be valid and accessible
- You'll receive AWS account verification emails
- Use email aliases or distribution lists for organizational accounts

### Example Configuration
```bash
# Set up for production environment
export ORG_NAME="ACME Corporation"
export AWS_REGION="ap-southeast-3"
export LOG_ARCHIVE_EMAIL="aws-logs@acme.com"
export SECURITY_AUDIT_EMAIL="aws-security@acme.com"
```

## Usage

### Basic Execution
```bash
./provision-aws-landing-zone.sh
```

### Step-by-Step Process

1. **Run the script:**
```bash
./provision-aws-landing-zone.sh
```

2. **Review the configuration:**
The script will display your settings and prompt for confirmation:
```
Configuration:
  Organization Name: MyOrganization
  AWS Region: ap-southeast-3
  Log Archive Email: aws-log-archive@yourdomain.com
  Security/Audit Email: aws-security-audit@yourdomain.com

Do you want to proceed? (yes/no):
```

3. **Monitor the progress:**
The script provides real-time progress updates with color-coded logging:
- 🟢 **GREEN** = Successful operations
- 🟡 **YELLOW** = Warnings or existing resources
- 🔴 **RED** = Errors or failures
- 🔵 **BLUE** = Debug information

4. **Review the output:**
Upon completion, you'll receive:
- Summary file: `landing-zone-summary-YYYYMMDD_HHMMSS.txt`
- Detailed log: `landing-zone-provisioning-YYYYMMDD_HHMMSS.log`

## What Gets Created

### 1. AWS Organization
- Organization ID
- Root organizational unit
- Feature set: ALL (enables SCPs, tag policies, backup policies)

### 2. Organizational Units (OUs)
- **Security OU**: For security and compliance accounts
- **Infrastructure OU**: For shared infrastructure accounts
- **Workloads OU**: For application workload accounts

### 3. Core Accounts
- **LogArchive Account**: Centralized log storage
- **SecurityAudit Account**: Security tooling and monitoring

### 4. Service Control Policies
- **DenyRootUserActions**: Restricts root user access
- **RequireMFAForActions**: Requires MFA for sensitive operations

### 5. CloudTrail Configuration
- Organization-wide trail
- S3 bucket with versioning and encryption
- Multi-region logging
- Log file validation enabled

### 6. AWS Service Integrations
- CloudTrail trusted access
- AWS Config trusted access
- IAM Identity Center (SSO) trusted access

## Post-Provisioning Steps

### Immediate Actions (Critical)

1. **Enable MFA on ALL root users:**
```bash
# Management Account
aws iam enable-mfa-device --user-name root --serial-number arn:aws:iam::ACCOUNT_ID:mfa/root --authentication-code-1 CODE1 --authentication-code-2 CODE2

# Repeat for Log Archive and Security/Audit accounts
```

2. **Delete root user access keys:**
```bash
aws iam list-access-keys --user-name root
aws iam delete-access-key --access-key-id ACCESS_KEY_ID --user-name root
```

3. **Configure account contact information:**
- Log into each account console
- Navigate to Account Settings
- Update primary, billing, and security contacts

### Security Configuration

4. **Set up IAM Identity Center (AWS SSO):**
```bash
# Enable AWS SSO
aws sso-admin create-instance

# Configure identity source (Active Directory, Okta, etc.)
# Create permission sets for different roles
# Assign users to accounts
```

5. **Enable AWS Config in all accounts:**
```bash
# In each account
aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT_ID:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig
aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=config-bucket-ACCOUNT_ID
aws configservice start-configuration-recorder --configuration-recorder-name default
```

6. **Configure AWS Security Hub:**
```bash
# In Security/Audit account
aws securityhub enable-security-hub --enable-default-standards

# Enable delegated administrator
aws organizations enable-aws-service-access --service-principal securityhub.amazonaws.com
aws securityhub enable-organization-admin-account --admin-account-id SECURITY_ACCOUNT_ID
```

7. **Set up GuardDuty:**
```bash
# In Security/Audit account
aws guardduty create-detector --enable

# Enable delegated administrator
aws guardduty enable-organization-admin-account --admin-account-id SECURITY_ACCOUNT_ID
```

### Governance & Compliance

8. **Configure billing alerts:**
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name billing-alert \
  --alarm-description "Alert when monthly costs exceed threshold" \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 21600 \
  --evaluation-periods 1 \
  --threshold 1000 \
  --comparison-operator GreaterThanThreshold
```

9. **Implement tagging strategy:**
```bash
# Example: Create tag policies
aws organizations create-policy \
  --content file://tag-policy.json \
  --description "Organization tag policy" \
  --name TagPolicy \
  --type TAG_POLICY
```

10. **Set up AWS Backup:**
```bash
# Create backup vault in Log Archive account
aws backup create-backup-vault --backup-vault-name OrgBackupVault

# Configure backup plans
aws backup create-backup-plan --backup-plan file://backup-plan.json
```

## Verification

### Verify Organization Structure
```bash
# List organization details
aws organizations describe-organization

# List all accounts
aws organizations list-accounts

# List organizational units
aws organizations list-organizational-units-for-parent --parent-id ROOT_ID

# List policies
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
```

### Verify CloudTrail
```bash
# Check trail status
aws cloudtrail get-trail-status --name organization-trail

# Verify logging to S3
aws s3 ls s3://cloudtrail-logs-ACCOUNT_ID/AWSLogs/
```

### Verify Account Access
```bash
# Assume role into new accounts (requires role creation first)
aws sts assume-role \
  --role-arn arn:aws:iam::LOG_ARCHIVE_ACCOUNT_ID:role/OrganizationAccountAccessRole \
  --role-session-name test-session
```

## Troubleshooting

### Common Issues

**Issue: "Email address already in use"**
```
Solution: Each AWS account requires a unique email address.
Use email aliases (e.g., aws+logarchive@domain.com) or different emails.
```

**Issue: "Account creation taking too long"**
```
Solution: Account creation typically takes 2-5 minutes but can take up to 30 minutes.
The script will wait up to 10 minutes and timeout with an error.
Check the AWS Organizations console for account status.
```

**Issue: "Insufficient permissions"**
```
Solution: Ensure you're running from the Management Account with appropriate permissions.
Required: organizations:*, iam:*, cloudtrail:*, s3:*
```

**Issue: "Organization already exists"**
```
Solution: If an organization already exists, the script will detect and continue.
Review existing structure before proceeding.
```

### Debug Mode

Enable detailed logging:
```bash
set -x  # Enable bash debug mode
./provision-aws-landing-zone.sh
```

Check detailed logs:
```bash
tail -f landing-zone-provisioning-*.log
```

## Cost Considerations

### Free Tier Resources
- AWS Organizations: No additional charge
- CloudTrail: First trail in each region is free
- S3 storage: Pay only for actual log storage (typically <$1/month initially)

### Ongoing Costs (Approximate)
- **S3 Storage**: ~$0.023 per GB/month (CloudTrail logs)
- **CloudTrail**: Free for first trail, $2/100,000 events for additional
- **AWS Config**: ~$2/active rule/region/month (if enabled)
- **Security Hub**: ~$0.001 per finding (if enabled)
- **GuardDuty**: ~$1.18 per 1M events analyzed (if enabled)

**Estimated Monthly Cost**: $5-50 for basic Landing Zone (without workload accounts)

## Security Best Practices

### Root Account Security
1. ✓ Enable MFA on all root accounts
2. ✓ Delete root access keys
3. ✓ Use root account only for emergency access
4. ✓ Document and secure root credentials in vault
5. ✓ Set up account recovery contacts

### Access Management
1. ✓ Use IAM Identity Center (SSO) for user access
2. ✓ Implement least-privilege access
3. ✓ Enforce MFA for all console access
4. ✓ Use temporary credentials (STS)
5. ✓ Regular access review and auditing

### Monitoring & Logging
1. ✓ Enable CloudTrail in all regions and accounts
2. ✓ Configure log file validation
3. ✓ Set up CloudWatch alarms for suspicious activity
4. ✓ Enable AWS Config for compliance monitoring
5. ✓ Review logs regularly

### Network Security
1. ✓ Use VPC for all workload accounts
2. ✓ Implement network segmentation
3. ✓ Enable VPC Flow Logs
4. ✓ Use AWS Shield for DDoS protection
5. ✓ Implement AWS WAF for web applications

## Rollback and Cleanup

### Remove Landing Zone Resources

**WARNING**: This will delete all created resources and accounts. This action is irreversible.

```bash
# Delete accounts (must be done manually via console)
# 1. Remove all resources from accounts
# 2. Close accounts in AWS Organizations console
# 3. Wait 90 days for permanent deletion

# Delete CloudTrail
aws cloudtrail delete-trail --name organization-trail

# Delete S3 bucket (must be empty first)
aws s3 rb s3://cloudtrail-logs-ACCOUNT_ID --force

# Detach and delete SCPs
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations detach-policy --policy-id POLICY_ID --target-id OU_ID
aws organizations delete-policy --policy-id POLICY_ID

# Delete OUs (must be empty first)
aws organizations delete-organizational-unit --organizational-unit-id OU_ID

# Delete organization (must have no member accounts except management)
aws organizations delete-organization
```

## Advanced Configuration

### Custom SCPs

Create custom Service Control Policies:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:RunInstances"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "ec2:InstanceType": [
            "t3.micro",
            "t3.small"
          ]
        }
      }
    }
  ]
}
```

Apply SCP:
```bash
aws organizations create-policy \
  --content file://custom-scp.json \
  --description "Restrict EC2 instance types" \
  --name RestrictEC2Types \
  --type SERVICE_CONTROL_POLICY

aws organizations attach-policy \
  --policy-id POLICY_ID \
  --target-id OU_ID
```

### Cross-Account Roles

Create cross-account access roles:

```bash
# In target account (e.g., LogArchive)
aws iam create-role \
  --role-name CrossAccountReadOnly \
  --assume-role-policy-document file://trust-policy.json

aws iam attach-role-policy \
  --role-name CrossAccountReadOnly \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Assume role from management account
aws sts assume-role \
  --role-arn arn:aws:iam::LOG_ARCHIVE_ACCOUNT:role/CrossAccountReadOnly \
  --role-session-name read-session
```

## Support and Contribution

### Getting Help
- Review the detailed logs in `landing-zone-provisioning-*.log`
- Check AWS Organizations console for account status
- Consult AWS documentation: https://docs.aws.amazon.com/organizations/

### Contributing
Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## References

### AWS Documentation
- [AWS Organizations User Guide](https://docs.aws.amazon.com/organizations/)
- [AWS Control Tower User Guide](https://docs.aws.amazon.com/controltower/)
- [Multi-Account Framework](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/)
- [AWS Landing Zone](https://aws.amazon.com/solutions/implementations/aws-landing-zone/)
- [Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)

### Best Practices
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [Security Best Practices](https://docs.aws.amazon.com/security/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)

## License

This script is provided as-is under the Apache ver-2.0 License. See LICENSE file for details.

## Changelog

### Version 1.0.0 (2025-11-03)
- Initial release
- AWS Organizations setup
- Core account provisioning
- SCP creation and attachment
- CloudTrail organization trail
- Comprehensive logging and error handling
- Summary report generation

## Copyright

- Author: **DevOps Engineer (support.gxc@xapiens.id)**
- Vendor: **Xapiens Teknologi Indonesia (xapiens.id)**
- License: **Apache v2**

---

- **Maintained by**: DevOps Team
- **Last Updated**: 2025-11-03
- **Version**: 1.0.0