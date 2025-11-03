# Post-Deployment Automation Guide

## 🎯 Overview

The **post-deployment-automation.sh** script automates all 10 critical next steps after your AWS Landing Zone is provisioned. This saves hours of manual configuration and ensures consistent, best-practice implementation.

---

## 📋 What Gets Automated

### ✅ Fully Automated (No Manual Steps)
1. **IAM Identity Center (AWS SSO)** - Enabled with default permission sets
2. **AWS Config** - Enabled in all 3 core accounts with centralized logging
3. **Security Hub** - Configured with delegated administration
4. **GuardDuty** - Enabled with auto-enable for new accounts
5. **Custom SCPs** - Regional restrictions and S3 encryption enforcement
6. **Cross-Account Roles** - ReadOnly and Admin roles with MFA
7. **AWS Backup** - Backup vault and daily backup plan configured
8. **Tagging Strategy** - Tag policies created and enforced

### 📖 Guided Automation (Minimal Manual Steps)
1. **MFA Configuration** - Detailed guide generated with account-specific instructions
2. **Workload Accounts** - Optional interactive creation of Dev/Prod accounts

---

## 🚀 Quick Start

### Prerequisites
```bash
# Must have completed initial Landing Zone provisioning
./provision-aws-landing-zone.sh

# Verify deployment
./verify-landing-zone.sh
```

### Execute Post-Deployment Automation
```bash
# Make executable
chmod +x post-deployment-automation.sh

# Run the automation
./post-deployment-automation.sh

# Follow prompts and confirm actions
```

**Execution Time:** 15-20 minutes

---

## 📊 Step-by-Step Breakdown

### Step 1: MFA Configuration Guide ✅ Automated
**What it does:**
- Generates detailed MFA setup guide for all 3 root accounts
- Includes console URLs and step-by-step instructions
- Provides verification commands

**Output:**
- `mfa-configuration-guide.txt`

**Manual action required:**
- Follow guide to enable MFA on each root account
- Use Google Authenticator, Authy, or hardware MFA device

**Time:** 10 minutes (manual)

---

### Step 2: IAM Identity Center (AWS SSO) ✅ Automated
**What it does:**
- Enables IAM Identity Center in your region
- Creates default permission sets:
  - AdministratorAccess (8-hour session)
  - ReadOnlyAccess (8-hour session)
- Generates configuration guide

**Output:**
- IAM Identity Center enabled
- `iam-identity-center-setup.txt`

**Manual follow-up:**
- Add users and groups
- Assign permission sets to accounts
- Enable MFA for SSO users

**Time:** Automated (5 minutes for follow-up)

---

### Step 3: AWS Config ✅ Automated
**What it does:**
- Creates S3 bucket in Log Archive account for Config logs
- Enables versioning and encryption on bucket
- Creates IAM roles for Config service
- Enables Config in all 3 accounts:
  - Management Account
  - Log Archive Account
  - Security/Audit Account
- Starts configuration recording

**Resources created:**
- S3 bucket: `aws-config-logs-{LOG_ARCHIVE_ACCOUNT_ID}`
- IAM roles: `AWSConfigRole-{ACCOUNT_ID}` (per account)
- Configuration recorders (per account)
- Delivery channels (per account)

**Cost impact:** ~$2/account/month

**Time:** Fully automated (3-5 minutes)

---

### Step 4: Security Hub ✅ Automated
**What it does:**
- Enables Security Hub in Security/Audit account
- Enables default security standards:
  - AWS Foundational Security Best Practices
  - CIS AWS Foundations Benchmark
- Configures Security/Audit account as delegated administrator
- Adds Management and Log Archive accounts as members

**Resources created:**
- Security Hub enabled with standards
- Delegated administration configured
- Member accounts enrolled

**Cost impact:** ~$0.001 per finding

**Time:** Fully automated (2-3 minutes)

---

### Step 5: GuardDuty ✅ Automated
**What it does:**
- Enables GuardDuty in Security/Audit account
- Sets finding publication frequency to 15 minutes
- Configures Security/Audit account as delegated administrator
- Enables auto-enable for new accounts
- Organization-wide protection activated

**Resources created:**
- GuardDuty detector
- Delegated admin configuration
- Auto-enable settings

**Cost impact:** ~$1.18 per 1M events

**Time:** Fully automated (2-3 minutes)

---

### Step 6: Workload Account Creation 📖 Interactive
**What it does:**
- Prompts for Development and Production account creation
- Creates accounts if confirmed
- Moves accounts to Workloads OU
- Waits for account activation

**Accounts created (optional):**
- Development Account
- Production Account

**Manual input required:**
- Unique email addresses for each account
- Confirmation to proceed

**Time:** 5-10 minutes (if creating accounts)

---

### Step 7: Custom SCP Implementation ✅ Automated
**What it does:**
- Creates regional restriction SCP (limits to approved regions)
- Creates S3 encryption enforcement SCP
- SCPs available for attachment to OUs

**SCPs created:**
1. **DenyUnapprovedRegions**
   - Restricts operations to: ap-southeast-1, ap-southeast-2, ap-southeast-3, us-east-1
   - Prevents accidental resource creation in other regions

2. **EnforceS3Encryption**
   - Requires AES256 or KMS encryption for all S3 uploads
   - Prevents unencrypted data storage

**Manual follow-up:**
- Attach SCPs to appropriate OUs via Organizations console
- Test SCPs in non-production first

**Time:** Fully automated (1 minute)

---

### Step 8: Cross-Account IAM Roles ✅ Automated
**What it does:**
- Creates cross-account roles in Log Archive and Security/Audit accounts
- Roles require MFA for assumption
- Trust relationship with Management Account

**Roles created:**
1. **CrossAccountReadOnly**
   - Read-only access to account resources
   - Attached policy: `ReadOnlyAccess`
   - Available in: Log Archive, Security/Audit

2. **CrossAccountAdmin** (Security/Audit only)
   - Full administrative access
   - Attached policy: `AdministratorAccess`
   - Available in: Security/Audit

**Usage example:**
```bash
# Assume ReadOnly role
aws sts assume-role \
  --role-arn arn:aws:iam::LOG_ARCHIVE_ID:role/CrossAccountReadOnly \
  --role-session-name my-session \
  --serial-number arn:aws:iam::MGMT_ID:mfa/username \
  --token-code 123456
```

**Time:** Fully automated (2-3 minutes)

---

### Step 9: AWS Backup Configuration ✅ Automated
**What it does:**
- Creates backup vault in Log Archive account
- Creates daily backup plan with lifecycle policies
- Sets up encryption and retention

**Resources created:**
- Backup vault: `OrganizationBackupVault`
- Backup plan: `DailyBackupPlan`
  - Schedule: Daily at 05:00 UTC
  - Retention: 365 days
  - Cold storage transition: 30 days
  - Completion window: 2 hours

**Manual follow-up:**
- Create backup selections to specify resources
- Test backup and restore procedures

**Cost impact:** Storage costs only (~$0.05/GB/month)

**Time:** Fully automated (1-2 minutes)

---

### Step 10: Tagging Strategy ✅ Automated
**What it does:**
- Creates organization-wide tag policy
- Enforces 4 mandatory tags on resources
- Generates tagging guide

**Mandatory tags:**
1. **Environment** - Production, Development, Staging, Test
2. **Owner** - Team or individual email
3. **CostCenter** - Department code for chargeback
4. **Project** - Project name or identifier

**Enforced for:**
- EC2 instances
- RDS databases
- S3 buckets
- Lambda functions

**Output:**
- `tagging-strategy-guide.txt`

**Manual follow-up:**
- Enable cost allocation tags in Billing console
- Train teams on tagging requirements
- Set up tag-based cost allocation reports

**Time:** Fully automated (1 minute)

---

## 📈 Execution Timeline

```
┌─────────────────────────────────────────────────┐
│ Post-Deployment Automation Timeline             │
├─────────────────────────────────────────────────┤
│                                                 │
│ Step 1: MFA Guide           [Manual - 10 min]   │
│ Step 2: IAM Identity Center [Automated - 1 min] │
│ Step 3: AWS Config          [Automated - 5 min] │
│ Step 4: Security Hub        [Automated - 3 min] │
│ Step 5: GuardDuty           [Automated - 3 min] │
│ Step 6: Workload Accounts   [Optional - 10 min] │
│ Step 7: Custom SCPs         [Automated - 1 min] │
│ Step 8: Cross-Account Roles [Automated - 3 min] │
│ Step 9: AWS Backup          [Automated - 2 min] │
│ Step 10: Tagging Strategy   [Automated - 1 min] │
│                                                 │
│ Total Automated Time: ~15-20 minutes            │
│ Total Manual Time: ~10-15 minutes               │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## 💰 Cost Impact

### Monthly Ongoing Costs (Additional)

| Service | Estimated Cost | Notes |
|---------|---------------|-------|
| AWS Config | $2-4/account | 3 accounts = $6-12/month |
| Security Hub | $1-5/month | Depends on findings |
| GuardDuty | $3-10/month | Based on events analyzed |
| AWS Backup | Storage only | ~$0.05/GB/month |
| **Total** | **$15-40/month** | Without workload accounts |

**With workload accounts added:** +$10-20/month per account

---

## 📁 Generated Files

After execution, you'll have:

1. **mfa-configuration-guide.txt**
   - Step-by-step MFA setup for all accounts
   - Console URLs and verification commands

2. **iam-identity-center-setup.txt**
   - IAM Identity Center configuration guide
   - Permission set details
   - User and group setup instructions

3. **tagging-strategy-guide.txt**
   - Mandatory tag definitions
   - Tagging examples by resource type
   - Cost allocation setup guide

4. **post-deployment-summary-[timestamp].txt**
   - Complete execution summary
   - Services enabled
   - Resources created
   - Next manual actions

5. **post-deployment-automation-[timestamp].log**
   - Detailed execution logs
   - Error messages (if any)
   - Timestamps for all actions

---

## 🔍 Verification

### Check Services Are Enabled

```bash
# Verify AWS Config
aws configservice describe-configuration-recorders
aws configservice describe-configuration-recorder-status

# Verify Security Hub
aws securityhub describe-hub
aws securityhub get-enabled-standards

# Verify GuardDuty
aws guardduty list-detectors
aws guardduty get-detector --detector-id DETECTOR_ID

# Verify IAM Identity Center
aws sso-admin list-instances

# List custom SCPs
aws organizations list-policies --filter SERVICE_CONTROL_POLICY

# List cross-account roles
aws iam list-roles --query 'Roles[?contains(RoleName, `CrossAccount`)]'

# Check AWS Backup
aws backup list-backup-vaults
aws backup list-backup-plans
```

---

## 🛠️ Troubleshooting

### Issue: "Cannot assume role in account"
**Solution:**
The script uses `OrganizationAccountAccessRole` which is created automatically when accounts are created via Organizations. If this fails:

```bash
# Check if role exists
aws iam get-role \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/OrganizationAccountAccessRole

# If missing, create it manually in the target account
```

### Issue: "Service already enabled"
**Solution:**
This is normal if you've run the script multiple times. The script is idempotent and will skip already-configured services with a warning.

### Issue: "Insufficient permissions"
**Solution:**
Ensure you're running from the Management Account with full administrative permissions:
- `organizations:*`
- `iam:*`
- `config:*`
- `securityhub:*`
- `guardduty:*`
- `backup:*`

### Issue: "Account creation timeout"
**Solution:**
Account creation can take up to 30 minutes. Check status manually:

```bash
aws organizations list-create-account-status
```

---

## 📚 Post-Automation Actions

### Immediate (Day 1)
1. ✅ Complete MFA setup (use generated guide)
2. ✅ Configure IAM Identity Center users
3. ✅ Review Security Hub findings
4. ✅ Test cross-account role access

### Week 1
1. ✅ Attach custom SCPs to OUs
2. ✅ Configure AWS Backup selections
3. ✅ Set up CloudWatch alarms for Security Hub
4. ✅ Train team on tagging strategy

### Month 1
1. ✅ Review Config compliance rules
2. ✅ Analyze GuardDuty findings
3. ✅ Create custom Config rules
4. ✅ Set up automated remediation

---

## 🎓 Advanced Customization

### Add Custom Config Rules

```bash
# Example: Require tags on EC2 instances
aws configservice put-config-rule \
  --config-rule file://custom-config-rule.json
```

### Create Additional SCPs

```bash
# Example: Deny instance types
aws organizations create-policy \
  --content file://deny-large-instances-scp.json \
  --description "Restrict expensive instance types" \
  --name "DenyLargeInstances" \
  --type SERVICE_CONTROL_POLICY
```

### Add More Backup Plans

```bash
# Example: Weekly backup plan
aws backup create-backup-plan \
  --backup-plan file://weekly-backup-plan.json
```

---

## 🔒 Security Considerations

### IAM Roles Created
All cross-account roles require MFA for assumption, following security best practices.

### Service Permissions
The script creates service-linked roles with minimum required permissions for:
- AWS Config
- Security Hub
- GuardDuty
- AWS Backup

### Data Encryption
All services are configured with encryption:
- Config logs: AES256
- Backup vault: Default encryption
- S3 buckets: AES256

---

## 📊 Success Metrics

After running the automation, you should see:

✅ **Compliance Score Increase**
- Security Hub compliance score should be visible
- Config compliance dashboard populated

✅ **Security Posture Improvement**
- GuardDuty actively monitoring threats
- Security Hub findings being generated
- Config recording all resource changes

✅ **Governance Implementation**
- 4 active SCPs (2 from initial setup + 2 custom)
- Tag policies enforced organization-wide
- Cross-account access centralized

✅ **Operational Readiness**
- Backup protection configured
- Centralized logging active
- IAM Identity Center ready for users

---

## 🔄 Re-running the Script

The script is **idempotent** - safe to run multiple times:
- Existing resources won't be duplicated
- Warnings shown for already-configured services
- New configurations will be added

**When to re-run:**
- After adding new accounts
- To update configurations
- To apply new custom SCPs
- After script updates

---

## 📞 Support

### Generated Documentation
All configuration details are in generated files:
- Check `mfa-configuration-guide.txt` for MFA help
- Review `iam-identity-center-setup.txt` for SSO guidance
- See `tagging-strategy-guide.txt` for tagging help

### Logs
Detailed execution logs in:
- `post-deployment-automation-[timestamp].log`

### AWS Documentation
- [AWS Config](https://docs.aws.amazon.com/config/)
- [Security Hub](https://docs.aws.amazon.com/securityhub/)
- [GuardDuty](https://docs.aws.amazon.com/guardduty/)
- [IAM Identity Center](https://docs.aws.amazon.com/singlesignon/)

---

## ✅ Completion Checklist

After running the automation:

- [ ] All steps completed without errors
- [ ] Summary report generated and reviewed
- [ ] MFA enabled on all root accounts
- [ ] IAM Identity Center users configured
- [ ] Security Hub findings reviewed
- [ ] GuardDuty monitoring active
- [ ] Custom SCPs attached to OUs
- [ ] Cross-account roles tested
- [ ] Backup selections configured
- [ ] Team trained on tagging strategy
- [ ] Cost allocation tags activated
- [ ] CloudWatch alarms configured

---

**🎉 Congratulations! Your AWS Landing Zone is now fully configured with enterprise-grade security and governance!**

---

## Quick Command Reference

```bash
# Run post-deployment automation
./post-deployment-automation.sh

# Verify all services
./verify-landing-zone.sh

# Check automation logs
tail -100 post-deployment-automation-*.log

# List all generated files
ls -lh mfa-configuration-guide.txt \
      iam-identity-center-setup.txt \
      tagging-strategy-guide.txt \
      post-deployment-summary-*.txt
```

## Copyright

- Author: **DevOps Engineer (support.gxc@xapiens.id)**
- Vendor: **Xapiens Teknologi Indonesia (xapiens.id)**
- License: **Apache v2**

---

- **Version:** 1.0.0
- **Last Updated:** 2025-11-03
- **Maintained by:** DevOps Team