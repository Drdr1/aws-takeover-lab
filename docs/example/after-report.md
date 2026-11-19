# Takeover report: after import and guardrails

Account `123456789012`, region `us-east-1`. Collected with read-only calls only.

| | |
|---|---|
| Resources found | 22 |
| Already in Terraform | 22 |
| Not in Terraform | 0 |
| Findings | 3 critical, 4 high, 6 medium |
| CloudTrail | account-audit |

## Findings

Nothing here is changed without a written change request and the owner's approval.

| Rule | Severity | Resource | Finding | Proposed fix |
|---|---|---|---|---|
| TKO-001 | critical | los-web (sg-6e7fa8ccc2b0f2ebf) | SSH (22) open to the whole internet | Remove the rule; reach hosts through SSM Session Manager (IAM-authenticated, logged in CloudTrail). |
| TKO-002 | critical | mismo-bridge (sg-dc898548d9e3ad093) | RDP (3389) open to the whole internet | Remove the rule; reach hosts through SSM Session Manager (IAM-authenticated, logged in CloudTrail). |
| TKO-009 | critical | prev-admin (prev-admin) | IAM user with full admin and a long-lived access key | Find where the key is used (CloudTrail, last-used date), move that use to a role, then deactivate and delete the key. |
| TKO-003 | high | los-db (los-db) | Database has a public endpoint | Set publicly_accessible = false; only the app and bridge security groups reach it. |
| TKO-004 | high | los-db (los-db) | Database storage and snapshots are not encrypted | Encryption can't be switched on in place: snapshot, copy the snapshot with a KMS key, restore, cut over in a maintenance window. |
| TKO-007 | high | acme-los-documents (acme-los-documents) | No S3 public access block | Add aws_s3_bucket_public_access_block with all four settings on. |
| TKO-010 | high | prev-admin (prev-admin) | IAM user without MFA | Require MFA or replace the user with SSO access. |
| TKO-005 | medium | los-db (los-db) | Only 1 day(s) of automated backups | Raise retention to at least 14 days and prove it with a quarterly restore test. |
| TKO-006 | medium | los-db (los-db) | Deletion protection is off | Turn on deletion_protection; one wrong apply should not be able to drop the system of record. |
| TKO-008 | medium | acme-los-documents (acme-los-documents) | Versioning is off, so overwrites and deletes are permanent | Enable versioning with a lifecycle rule for old versions. |
| TKO-012 | medium | los-web-01 (i-416bbd8f82f683b66) | IMDSv1 allowed on the instance | Require IMDSv2 tokens (metadata_options.http_tokens = required) after checking the app's SDK versions. |
| TKO-012 | medium | mismo-bridge-01 (i-f63df76d81c7e8a2e) | IMDSv1 allowed on the instance | Require IMDSv2 tokens (metadata_options.http_tokens = required) after checking the app's SDK versions. |
| TKO-013 | medium | los/db-master (arn:aws:secretsmanager:us-east-1:123456789012:secret:los/db-master-TYHoTO) | Secret is never rotated | Enable rotation; for the RDS master password, use RDS-managed rotation. |

## Inventory

| Type | Name | ID | Terraform |
|---|---|---|---|
| `aws_db_instance` | los-db | `los-db` | managed |
| `aws_db_subnet_group` | los-db-subnets | `los-db-subnets` | managed |
| `aws_iam_role` | los-app | `los-app` | managed |
| `aws_iam_role` | owner-break-glass | `owner-break-glass` | managed |
| `aws_iam_role` | terraform-deploy | `terraform-deploy` | managed |
| `aws_iam_user` | prev-admin | `prev-admin` | managed |
| `aws_instance` | los-web-01 | `i-416bbd8f82f683b66` | managed |
| `aws_instance` | mismo-bridge-01 | `i-f63df76d81c7e8a2e` | managed |
| `aws_internet_gateway` | los-prod-igw | `igw-7d0c748f7fe5bdc61` | managed |
| `aws_s3_bucket` | acme-audit-trail | `acme-audit-trail` | managed |
| `aws_s3_bucket` | acme-los-backups | `acme-los-backups` | managed |
| `aws_s3_bucket` | acme-los-documents | `acme-los-documents` | managed |
| `aws_s3_bucket` | acme-tfstate | `acme-tfstate` | managed |
| `aws_secretsmanager_secret` | los/db-master | `arn:aws:secretsmanager:us-east-1:123456789012:secret:los/db-master-TYHoTO` | managed |
| `aws_security_group` | los-db | `sg-b7c4a8c2b45f75bf7` | managed |
| `aws_security_group` | los-web | `sg-6e7fa8ccc2b0f2ebf` | managed |
| `aws_security_group` | mismo-bridge | `sg-dc898548d9e3ad093` | managed |
| `aws_subnet` | los-private-a | `subnet-c9459af7ddc6458fa` | managed |
| `aws_subnet` | los-private-b | `subnet-0ae48980642316940` | managed |
| `aws_subnet` | los-public-a | `subnet-752c5fc1db485df92` | managed |
| `aws_subnet` | los-public-b | `subnet-430c007d0716c0522` | managed |
| `aws_vpc` | los-prod | `vpc-edbdc102f4c0572d0` | managed |

## Diagram

```mermaid
flowchart LR
  internet(("Internet"))
  subgraph n0["VPC los-prod 10.20.0.0/16"]
    subgraph n2["los-public-a 10.20.1.0/24"]
      n9["los-web-01<br/>i-416bbd8f82f683b66<br/>linux t3.medium"]
    end
    subgraph n3["los-private-a 10.20.11.0/24"]
    end
    subgraph n4["los-public-b 10.20.2.0/24"]
      n10["mismo-bridge-01<br/>i-f63df76d81c7e8a2e<br/>windows t3.medium"]
    end
    subgraph n5["los-private-b 10.20.12.0/24"]
    end
    n12[("los-db<br/>postgres 16.3")]
  end
  internet -- 443 --> n9
  internet -. 22 .-> n9
  internet -. 3389 .-> n10
  n9 -- 5432 --> n12
  n10 -- 5432 --> n12
  n13[/"s3: acme-los-documents"/]
  n14[/"s3: acme-los-backups"/]
  n15[/"s3: acme-tfstate"/]
  n16[/"s3: acme-audit-trail"/]
```
