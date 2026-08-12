# AWS Cloud Security Audit — Full Report

## Executive summary

This exercise assessed a single AWS account against the CIS AWS Foundations Benchmark using Prowler. I intentionally introduced five common cloud misconfigurations, ran an automated audit, remediated the findings, and re-scanned to verify each fix.

Of the five simulated issues, three were fully remediated and confirmed by a second scan, one (EBS volume encryption) was documented as an AWS platform limitation with the correct remediation path noted, and one (an internet-open security group) was caught through manual verification after the automated scanner missed it. The automated critical-finding count for the account dropped from 5 to 4, with the eliminated critical being the publicly accessible S3 bucket.

The audit was conducted with a dedicated read-only IAM identity, ensuring the scanning tool never held permission to modify the environment it assessed.

---

## Methodology

1. **Environment setup** — Provisioned a small AWS environment in `us-east-1` with five deliberate misconfigurations, each tagged `Project=security-audit-lab`.
2. **Least-privilege scanner identity** — Created an IAM user (`prowler-scanner`) with only the `SecurityAudit` and `ViewOnlyAccess` managed policies, and configured a separate AWS CLI profile for it.
3. **Baseline scan** — Ran Prowler against the CIS AWS Foundations Benchmark, exporting HTML and JSON-ASFF output.
4. **Analysis & prioritization** — Reviewed findings, mapped them to CIS controls, and prioritized by severity.
5. **Remediation** — Fixed each issue via the AWS CLI following least-privilege and defense-in-depth principles.
6. **Verification** — Re-ran the identical scan and compared results to confirm remediation.
7. **Manual review** — Verified an exposure the automated scan did not surface.

**Tooling:** Prowler 5.37.1, AWS CLI v2, Python 3.12 (isolated virtual environment), Windows/PowerShell.

---

## Scan results

| Metric | Before | After |
|---|---|---|
| Total checks | 362 | 386 |
| Passed | 120 | 138 |
| Failed | 242 | 248 |
| Critical failures | 5 | 4 |
| High failures | 33 | 30 |
| Medium failures | 90 | 95 |
| Low failures | 114 | 119 |

**Why the total check count increased after remediation.** Enabling CloudTrail caused Prowler to evaluate roughly two dozen additional checks that were not assessable when no trail existed — for example, whether trail logs have file-validation enabled, whether they are encrypted at rest with KMS, and whether the log bucket has MFA delete. Because a minimum-viable trail was created (the goal being to remediate the "no logging" finding, not to build a hardened logging pipeline), several of these newly-evaluable checks register as failures. These are legitimate additional findings rather than regressions, and are noted below as optional follow-up hardening.

---

## Findings

### Finding 1 — Publicly accessible S3 bucket (Critical) — REMEDIATED

**CIS reference:** S3 public access controls.

**Description.** A bucket was configured with account/bucket-level Block Public Access disabled and a bucket policy granting `s3:GetObject` to `Principal: "*"`. A synthetic test object was confirmed readable over the public internet with no authentication.

**Remediation.**
- Deleted the public bucket policy.
- Re-enabled all four Block Public Access settings at the bucket level.

**Verification.** Post-remediation scan: "S3 bucket is not publicly accessible," "S3 bucket policy does not allow cross-account access," and "S3 bucket has Block Public Access…" all moved from FAILED to PASSED. The previously-public object URL now returns `AccessDenied`.

---

### Finding 2 — IAM role with AdministratorAccess (Critical) — REMEDIATED

**CIS reference:** Least-privilege / avoid `*:*` administrative policies.

**Description.** A service role (`audit-lab-overpermissive-role`, assumable by EC2) had the AWS-managed `AdministratorAccess` policy attached. A compromise of any instance assuming this role would have escalated to full account compromise.

**Remediation.**
- Detached `AdministratorAccess`.
- Attached the scoped `AmazonS3ReadOnlyAccess` policy, reflecting the role's actual need.

**Verification.** The role no longer appears among resources failing the confused-deputy / over-privilege checks tied to this role in the follow-up scan. (Note: the generic "Attached AWS-managed IAM policy does not allow '*:*'" check still lists the `AdministratorAccess` *policy object itself* as failing — this is expected, as the managed policy always exists in AWS; the point is that it is no longer attached to this role.)

---

### Finding 3 — CloudTrail not enabled (High) — REMEDIATED

**CIS reference:** Ensure CloudTrail is enabled in all regions.

**Description.** No CloudTrail trail existed, meaning there was no audit log of account activity — a critical gap for incident investigation and detection.

**Remediation.**
- Created a dedicated S3 log bucket with a bucket policy scoping write access to the CloudTrail service principal for this account only.
- Created and started a CloudTrail trail delivering to that bucket.

**Verification.** "Region has at least one CloudTrail trail logging" moved from FAILED to PASSED in `us-east-1`, and "CloudTrail trail S3 bucket is not publicly accessible" passes.

**Optional follow-up hardening (identified, out of scope).** The minimal trail leaves several CIS best-practices unmet: log-file validation, KMS encryption at rest for trail logs, MFA delete on the log bucket, and delivery to CloudWatch Logs. These are documented here as the natural next steps toward a production-grade logging posture.

---

### Finding 4 — Unencrypted EBS volume (Medium) — DOCUMENTED LIMITATION

**CIS reference:** Ensure EBS volume encryption.

**Description.** An 8 GiB `gp3` volume was created without encryption.

**Remediation path.** AWS does not support toggling encryption on an existing EBS volume in place. The supported remediation is to snapshot the volume, copy the snapshot with encryption enabled, and create a new encrypted volume from that copy — then migrate and retire the original. Additionally, EBS default encryption should be enabled at the account level so future volumes are encrypted automatically.

Because the volume was an empty lab resource, the migration was not performed; the remediation path is documented here as the correct real-world approach, and the finding remains FAILED in the after-scan by design.

---

### Finding 5 — Security group open to the internet on SSH/RDP (Critical) — MANUAL

**CIS reference:** No unrestricted ingress to remote administration ports.

**Description.** A security group (`audit-lab-open-sg`) permitted ingress from `0.0.0.0/0` on TCP 22 (SSH) and TCP 3389 (RDP).

**Automated-scan gap.** Prowler did **not** raise a finding for this group. Its internet-exposure checks evaluate security groups attached to live resources (instances, ENIs); because this group was not attached to a running resource at scan time, it was not treated as active attack surface and was skipped.

**Manual verification.** Confirmed via CLI:

```
$ aws ec2 describe-security-groups --group-names audit-lab-open-sg --query "SecurityGroups[0].IpPermissions" --output table

| FromPort | IpProtocol | ToPort | CidrIp    |
|----------|------------|--------|-----------|
| 22       | tcp        | 22     | 0.0.0.0/0 |
| 3389     | tcp        | 3389   | 0.0.0.0/0 |
```

**Remediation.**
- Revoked both `0.0.0.0/0` ingress rules.
- Re-added SSH (22) scoped to a single trusted `/32` source address.

**Takeaway.** This finding demonstrates why automated scanning and manual review are complementary. An automated tool reduces effort at scale but has coverage boundaries; a reviewer who understands those boundaries catches what the tool structurally cannot.

---

## Remaining critical findings (expected / out of scope)

Four critical findings remain in the after-scan. None are simulated misconfigurations; they reflect the real account's baseline:

- The `AdministratorAccess` managed policy object exists in AWS (always present) and is attached to the genuine account-admin user, which legitimately requires it.
- Root account MFA posture checks (hardware MFA), which relate to the real account's root configuration rather than the lab.

These are noted for completeness and were intentionally left unchanged, as altering the account's genuine administrative access was outside the scope of this lab.

---

## Conclusion

The audit successfully identified and remediated the introduced misconfigurations, with every automated fix verified by re-scan and the two non-automated cases (EBS encryption, open security group) handled through documented reasoning and manual verification respectively. The exercise reinforces three practices central to cloud security work: verify remediation rather than assume it, treat automated tooling as one layer rather than the whole assessment, and apply least privilege even to the tools performing the audit.
