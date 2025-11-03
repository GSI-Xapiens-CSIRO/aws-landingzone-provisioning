# AWS Landing Zone - Quick Start Guide

## 5-Minute Setup

### Prerequisites Check
```bash
# Verify tools are installed
aws --version    # Should be 2.x or later
jq --version     # JSON processor
bash --version   # Should be 4.x or later

# Verify AWS credentials
aws sts get-caller-identity
```

### Step 1: Download Scripts
```bash
# Make scripts executable
chmod +x provision-aws-landing-zone.sh
chmod +x verify-landing-zone.sh
```

### Step 2: Configure Environment
```bash
# Copy example config
cp .env.example .env

# Edit configuration (REQUIRED)
nano .env

# Set these values:
export LOG_ARCHIVE_EMAIL="aws-logs@yourdomain.com"
export SECURITY_AUDIT_EMAIL="aws-security@yourdomain.com"
export ORG_NAME="MyCompany"
export AWS_REGION="ap-southeast-3"

# Load configuration
source .env
```

### Step 3: Run Provisioning
```bash
# Execute the provisioning script
./provision-aws-landing-zone.sh

# When prompted, type 'yes' to confirm
# Wait 10-15 minutes for completion
```

### Step 4: Verify Deployment
```bash
# Run verification script
./verify-landing-zone.sh

# Review the output for any failed checks
```

### Step 5: Critical Post-Deployment Actions
```bash
# 1. Enable MFA on Management Account (do this NOW!)
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name root-mfa \
  --outfile /tmp/QRCode.png \
  --bootstrap-method QRCodePNG

# 2. Check your email for Log Archive and Security/Audit account invitations
# 3. Log into each new account and enable MFA on root users
# 4. Delete any root access keys (if they exist)
```

## What You Get

✓ **AWS Organization** with all features enabled
✓ **3 Accounts**: Management, LogArchive, SecurityAudit
✓ **3 OUs**: Security, Infrastructure, Workloads
✓ **2 SCPs**: DenyRootUserActions, RequireMFAForActions
✓ **CloudTrail** organization trail with S3 logging
✓ **Service Integrations** for CloudTrail, Config, SSO

## Account Access

### Account IDs
```bash
# Get all account IDs
aws organizations list-accounts --query 'Accounts[*].[Name,Id,Status]' --output table
```

### Initial Access
1. Management Account: Already have access
2. Log Archive Account: Check email for invitation
3. Security/Audit Account: Check email for invitation

### Cross-Account Access (After Role Setup)
```bash
# Assume role in Log Archive account
aws sts assume-role \
  --role-arn arn:aws:iam::LOG_ARCHIVE_ACCOUNT_ID:role/OrganizationAccountAccessRole \
  --role-session-name admin-session
```

## Common Commands

### List Organization Structure
```bash
# View organization details
aws organizations describe-organization

# List all accounts
aws organizations list-accounts

# List OUs
aws organizations list-organizational-units-for-parent \
  --parent-id $(aws organizations list-roots --query 'Roots[0].Id' --output text)

# List SCPs
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
```

### CloudTrail Status
```bash
# Check trail status
aws cloudtrail get-trail-status --name organization-trail

# View recent events
aws cloudtrail lookup-events --max-results 10
```

### Billing
```bash
# View current month costs
aws ce get-cost-and-usage \
  --time-period Start=$(date -d "$(date +%Y-%m-01)" +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity MONTHLY \
  --metrics UnblendedCost
```

## Troubleshooting

### Issue: Account creation failed
```bash
# Check account creation status
aws organizations list-create-account-status

# Review specific request
aws organizations describe-create-account-status \
  --create-account-request-id REQUEST_ID
```

### Issue: Email already in use
```bash
# Use email aliases or different addresses
# Examples:
# aws+logs@domain.com
# aws-logs@domain.com
# logs@aws.domain.com
```

### Issue: CloudTrail not logging
```bash
# Start trail
aws cloudtrail start-logging --name organization-trail

# Verify
aws cloudtrail get-trail-status --name organization-trail
```

## Security Checklist

- [ ] MFA enabled on Management Account root user
- [ ] MFA enabled on Log Archive Account root user
- [ ] MFA enabled on Security/Audit Account root user
- [ ] All root access keys deleted
- [ ] CloudTrail is actively logging
- [ ] S3 bucket versioning and encryption enabled
- [ ] SCPs attached to appropriate OUs
- [ ] Account contact information updated
- [ ] Billing alerts configured

## Cost Estimate

### Initial Setup
- Account creation: **FREE**
- AWS Organizations: **FREE**
- CloudTrail (first trail): **FREE**

### Monthly Ongoing
- S3 storage (logs): **~$1-5/month**
- CloudTrail events: **~$0-2/month**
- **Total: ~$3-10/month** (without workloads)

## Next Steps

1. **Security**
   - Set up IAM Identity Center (SSO)
   - Enable AWS Config
   - Configure Security Hub
   - Enable GuardDuty

2. **Governance**
   - Create additional SCPs
   - Set up tag policies
   - Configure backup policies
   - Implement naming standards

3. **Workloads**
   - Create development account
   - Create production account
   - Set up VPC architecture
   - Deploy applications

## Support Resources

### Documentation
- [AWS Organizations](https://docs.aws.amazon.com/organizations/)
- [AWS Control Tower](https://docs.aws.amazon.com/controltower/)
- [Landing Zone Best Practices](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/)

### AWS Support
- AWS Support Center: https://console.aws.amazon.com/support/
- AWS Forums: https://forums.aws.amazon.com/
- AWS re:Post: https://repost.aws/

### Emergency Contacts
- AWS Abuse: abuse@amazonaws.com
- AWS Security: aws-security@amazon.com

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                  AWS LANDING ZONE OVERVIEW                  │
├─────────────────────────────────────────────────────────────┤
│ Management Account:     [Your original AWS account]         │
│ Log Archive Account:    [Created by script]                 │
│ Security/Audit Account: [Created by script]                 │
├─────────────────────────────────────────────────────────────┤
│ CloudTrail Bucket:      cloudtrail-logs-ACCOUNT_ID          │
│ Organization Trail:     organization-trail                  │
├─────────────────────────────────────────────────────────────┤
│ Security OU:            Contains Security/Audit             │
│ Infrastructure OU:      Contains Log Archive                │
│ Workloads OU:           Ready for applications              │
└─────────────────────────────────────────────────────────────┘

CRITICAL ACTIONS AFTER DEPLOYMENT:
1. Enable MFA on ALL root accounts
2. Delete root access keys
3. Set up IAM Identity Center
4. Configure AWS Config
5. Enable Security Hub & GuardDuty
```

## Version History

- **v1.0.0** (2025-11-03): Initial release

---

- **Questions?** Review the full README.md for detailed documentation.
- **Issues?** Run `./verify-landing-zone.sh` to diagnose problems.