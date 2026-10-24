# AWS Cloud Security Audit: Full Report

A hands-on cloud security audit of a single AWS account. Demonstrated skills include deploying a deliberately misconfigured environment, auditing it with Prowler against the CIS AWS Foundations Benchmark, remediating the findings with the AWS CLI, and verifying each fix with a second scan.

## Overview

This project simulates a small cloud environment with five common misconfigurations. I ran an automated audit, fixed what I could, and re-scanned to confirm each change. Three issues were fully remediated and verified, one was documented as an AWS platform limitation, and one was caught through manual review after the automated scanner missed it.

The scan was run with a dedicated read-only IAM identity, so the audit tool never had permission to modify the environment it assessed.

**What this demonstrates:**
- Cloud security auditing against an industry benchmark (CIS AWS Foundations)
- Least-privilege access design, including for the scanning tool itself
- Misconfiguration remediation across IAM, S3, EC2, and CloudTrail
- Verifying fixes with a before and after comparison instead of assuming they worked
- Knowing the limits of automated tooling and filling the gaps with manual review

| Category | Details |
|---|---|
| **Cloud** | AWS (Free Tier) |
| **Audit tool** | Prowler 5.37.1 |
| **Benchmark** | CIS AWS Foundations |
| **Scope** | Single account, `us-east-1` |
| **Simulated misconfigurations** | 5 |
| **Fully remediated & verified** | 3 |
| **Documented limitation / manual finding** | 2 |

## Methodology

1. **Environment setup:** Provisioned a small AWS environment in `us-east-1` with five deliberate misconfigurations, each tagged `Project=security-audit-lab`.
2. **Least-privilege scanner identity:** Created an IAM user (`prowler-scanner`) with only the `SecurityAudit` and `ViewOnlyAccess` managed policies, and configured a separate AWS CLI profile for it.
3. **Baseline scan:** Ran Prowler against the CIS AWS Foundations Benchmark and exported HTML and JSON-ASFF output.
4. **Analysis and prioritization:** Reviewed the findings, mapped them to CIS controls, and prioritized by severity.
5. **Remediation:** Fixed each issue through the AWS CLI following least-privilege and defense-in-depth principles.
6. **Verification:** Re-ran the identical scan and compared results to confirm each fix.
7. **Manual review:** Verified an exposure the automated scan did not surface.

## Issues Tested

| Issue | Severity | CIS Area | Result |
|---|---|---|---|
| Publicly accessible S3 bucket | Critical | S3 public access controls | Remediated and verified |
| IAM role with AdministratorAccess | Critical | Least privilege | Remediated and verified |
| CloudTrail not enabled | High | Logging in all regions | Remediated and verified |
| Unencrypted EBS volume | Medium | EBS volume encryption | Documented limitation |
| Security group open on SSH/RDP | Critical | Remote administration exposure | Manual finding, remediated |

## Scan Results

| Metric | Before | After |
|---|---|---|
| Total checks | 362 | 386 |
| Passed | 120 | 138 |
| Failed | 242 | 248 |
| Critical failures | 5 | 4 |
| High failures | 33 | 30 |
| Medium failures | 90 | 95 |
| Low failures | 114 | 119 |

**Why the total check count went up.** Enabling CloudTrail caused Prowler to evaluate about two dozen checks that were not assessable when no trail existed, such as whether trail logs have file validation enabled, whether they are encrypted at rest with KMS, and whether the log bucket has MFA delete. I created a minimal trail because the goal was to fix the "no logging" finding, not to build a hardened logging pipeline, so several of these new checks fail. They are legitimate additional findings and not regressions, and they are listed under Finding 3 as optional follow-up hardening.

## Key Findings

- The automated critical-finding count dropped from **5 to 4**, and the critical that was eliminated was the publicly accessible S3 bucket.
- Three of the five simulated issues were fixed and confirmed by a second scan, with the relevant checks moving from FAILED to PASSED.
- Prowler **did not flag** the open security group at all, so it was only caught through manual CLI verification.
- EBS encryption cannot be toggled on an existing volume, so the correct migration path was documented instead of performed.

## Findings

### Finding 1: Publicly accessible S3 bucket (Critical)

**Status:** Remediated

**Description:** A bucket was configured with Block Public Access disabled and a bucket policy granting `s3:GetObject` to `Principal: "*"`. A synthetic test object was confirmed readable over the public internet with no authentication.

**Remediation:**
- Deleted the public bucket policy
- Re-enabled all four Block Public Access settings at the bucket level

**Verification:** After remediation, the checks "S3 bucket is not publicly accessible," "S3 bucket policy does not allow cross-account access," and "S3 bucket has Block Public Access" all moved from FAILED to PASSED. The previously public object URL now returns `AccessDenied`.

### Finding 2: IAM role with AdministratorAccess (Critical)

**Status:** Remediated

**Description:** A service role (`audit-lab-overpermissive-role`, assumable by EC2) had the AWS-managed `AdministratorAccess` policy attached. A compromise of any instance assuming this role would have escalated to full account compromise.

**Remediation:**
- Detached `AdministratorAccess`
- Attached the scoped `AmazonS3ReadOnlyAccess` policy, which matches what the role actually needs

**Verification:** The role no longer appears among the resources failing the over-privilege checks tied to it in the follow-up scan. The generic check "Attached AWS-managed IAM policy does not allow '*:*'" still lists the `AdministratorAccess` policy object itself as failing. This is expected, since the managed policy always exists in AWS. What matters is that it is no longer attached to this role.

### Finding 3: CloudTrail not enabled (High)

**Status:** Remediated

**Description:** No CloudTrail trail existed, which meant there was no audit log of account activity. That is a major gap for incident investigation and detection.

**Remediation:**
- Created a dedicated S3 log bucket with a bucket policy limiting write access to the CloudTrail service principal for this account only
- Created and started a CloudTrail trail delivering to that bucket

**Verification:** "Region has at least one CloudTrail trail logging" moved from FAILED to PASSED in `us-east-1`, and "CloudTrail trail S3 bucket is not publicly accessible" passes.

**Optional follow-up hardening (out of scope):** The minimal trail leaves several CIS best practices unmet. These are log-file validation, KMS encryption at rest for trail logs, MFA delete on the log bucket, and delivery to CloudWatch Logs. They are the natural next steps toward a production-grade logging setup.

### Finding 4: Unencrypted EBS volume (Medium)

**Status:** Documented limitation

**Description:** An 8 GiB `gp3` volume was created without encryption.

**Remediation path:** AWS does not support turning on encryption for an existing EBS volume in place. The supported approach is to snapshot the volume, copy the snapshot with encryption enabled, create a new encrypted volume from that copy, then migrate and retire the original. EBS default encryption should also be enabled at the account level so future volumes are encrypted automatically.

Because the volume was an empty lab resource, I did not perform the migration. The path is documented here as the correct real-world approach, and the finding remains FAILED in the after-scan by design.

### Finding 5: Security group open to the internet on SSH/RDP (Critical)

**Status:** Manual finding, remediated

**Description:** A security group (`audit-lab-open-sg`) allowed ingress from `0.0.0.0/0` on TCP 22 (SSH) and TCP 3389 (RDP).

**Automated scan gap:** Prowler did **not** raise a finding for this group. Its internet-exposure checks evaluate security groups attached to live resources (instances, ENIs). Because this group was not attached to a running resource at scan time, it was not treated as active attack surface and was skipped.

**Manual verification:** Confirmed through the CLI:

```
$ aws ec2 describe-security-groups --group-names audit-lab-open-sg --query "SecurityGroups[0].IpPermissions" --output table

| FromPort | IpProtocol | ToPort | CidrIp    |
|----------|------------|--------|-----------|
| 22       | tcp        | 22     | 0.0.0.0/0 |
| 3389     | tcp        | 3389   | 0.0.0.0/0 |
```

**Remediation:**
- Revoked both `0.0.0.0/0` ingress rules
- Re-added SSH (22) scoped to a single trusted `/32` source address

**Takeaway:** Automated scanning and manual review complement each other. A tool reduces effort at scale but has coverage boundaries, and a reviewer who understands those boundaries can catch what the tool structurally cannot.

## Remaining Critical Findings

Four critical findings remain in the after-scan. None of them are simulated misconfigurations. They reflect the real account's baseline:

- The `AdministratorAccess` managed policy object exists in AWS (it is always present) and is attached to the genuine account admin user, which legitimately requires it
- Root account MFA posture checks (hardware MFA), which relate to the real account's root configuration and not the lab

I left these unchanged on purpose, since altering the account's genuine administrative access was outside the scope of this lab.

## Conclusion

The audit identified and remediated the introduced misconfigurations. Every automated fix was verified by re-scan, and the two non-automated cases were handled through documented reasoning (EBS encryption) and manual verification (the open security group). The exercise reinforced three practices that matter in cloud security work: verify remediation instead of assuming it, treat automated tooling as one layer and not the whole assessment, and apply least privilege even to the tools performing the audit.

## Tools Used

- **Prowler 5.37.1:** Automated audit against the CIS AWS Foundations Benchmark
- **AWS CLI v2:** Environment setup, remediation, and manual verification
- **Python 3.12:** Isolated virtual environment for running Prowler
- **Windows / PowerShell:** Local working environment

## Skills Demonstrated

`Cloud security auditing` · `AWS IAM/S3/EC2/CloudTrail` · `CIS Benchmark compliance` · `misconfiguration remediation` · `least-privilege access design` · `automated vs. manual verification`

---

*This is a self-directed lab project built for learning and portfolio purposes. All misconfigurations were introduced in a personally owned AWS account.*
