# aws-takeover-lab

How I take over an AWS account that someone else built by hand: understand it before touching it, bring it under Terraform without changing anything, and put the guardrails in place that let the owner stay in control of their account.

The whole sequence runs end to end in CI against [moto](https://github.com/getmoto/moto), a local AWS API emulator, with both Terraform and OpenTofu. No real account is needed to check the work.

```
1. seed        the previous engineer's hand-built environment (no Terraform anywhere)
2. inventory   read-only discovery -> inventory, findings, report, diagram
3. bootstrap   owner creates the state bucket, deploy role and admin boundary
4. guardrails  owner creates the SSN key and an Object Lock audit trail
5. codegen     inventory -> Terraform code + import blocks
6. import      plan must be imports only -> apply -> re-plan must be empty
7. drift       someone opens Postgres to a home IP in the console; the drift check names it
8. inventory   again, with Terraform state, for coverage
```

Example output from a real run is in [`docs/example/`](docs/example/): the [week-one report](docs/example/before-report.md), the [generated Terraform](docs/example/terraform/), the [drift report](docs/example/drift.md) and the [report after import](docs/example/after-report.md).

## 1. Inventory first, changes later

`python -m takeover inventory` makes only `Describe*`, `List*` and `Get*` calls. A test records every API call the inventory makes against moto and fails if any call is not a read or is not allowed by [`policies/inventory-readonly.json`](policies/inventory-readonly.json). That policy explicitly denies `secretsmanager:GetSecretValue`, `s3:GetObject` and `kms:Decrypt`: an inventory has no reason to read data.

The output is one data model, so the report, the findings and the generated code can't disagree:

- **`inventory.json`**: every VPC, subnet, security group, instance, database, bucket, IAM principal and secret, each marked as Terraform-managed or not.
- **`findings.json`, `report.md`**: 13 rules (TKO-001 to TKO-013), such as SSH or RDP open to the internet, a public or unencrypted database, too few days of backups, deletion protection off, missing public access blocks, admin users with long-lived keys, no CloudTrail, IMDSv1, and secrets that are never rotated. Each finding comes with the proposed fix.
- **`diagram.mmd`**: a Mermaid diagram of the network, with dotted lines where remote-admin ports face the internet.

## 2. Terraform import with a zero-diff gate

`python -m takeover codegen` writes Terraform that reads like a person wrote it, not a raw dump:

- IDs become references: `vpc_id = aws_vpc.los_prod.id`, `security_groups = [aws_security_group.los_web.id]`.
- Resources are split by layer: `network.tf`, `security_groups.tf`, `compute.tf`, `database.tf`, `storage.tf`, `identity.tf`, `secrets.tf`.
- Every finding is written above the resource it applies to (`# TKO-001 (critical): SSH (22) open to the whole internet`), with a note that the code reproduces the resource exactly as found and the fix is a separate, approved change.
- Resources already in someone's Terraform (by tag or by state) are skipped, so nothing is imported twice.

Then two gates:

1. **`check-import`** reads `terraform show -json` of the import plan and fails if anything would be created, replaced, destroyed or changed in AWS. The only exceptions are listed by name: Terraform-only arguments such as `skip_final_snapshot` or `recovery_window_in_days`, which exist only in state and cause no API call. That is why the apply says `21 imported, 2 changed`. Those 2 are state-only.
2. After the apply, `plan -detailed-exitcode` must return 0: **no changes**. That empty plan is the proof that the code describes the account exactly.

`terraform/environment/backend.tf` puts state in the S3 bucket from bootstrap with S3-native locking (`use_lockfile`), no DynamoDB table.

## 3. Owner guardrails: who can do what

| Principal | Used by | Can | Cannot |
|---|---|---|---|
| `owner-break-glass` | the business owner, MFA required | everything; applies the guardrails stack; manages the SSN key | (it is the top) |
| `terraform-deploy` | the sysadmin (me), CI | run the environment: EC2, RDS, S3, SSM, the state bucket, IAM roles *with the same boundary* | touch the owner's principals, remove or edit its own boundary, create roles or users without it, stop or delete CloudTrail, use or re-policy the SSN key, change the state bucket's policy, touch account or billing settings |
| `los-app` | the LOS application | decrypt SSNs, only with the `borrower-ssn` encryption context | anything else with the key |

- [`policies/admin-boundary.json.tftpl`](policies/admin-boundary.json.tftpl): the permissions boundary on every admin and deploy role.
- [`policies/ssn-key.json.tftpl`](policies/ssn-key.json.tftpl): the SSN key policy. It has **no "account root gets `kms:*`" statement**, because that statement would let any IAM admin grant themselves `Decrypt`.
- [`policies/state-bucket.json.tftpl`](policies/state-bucket.json.tftpl): TLS only, and only the deploy and owner roles can read or write state.
- [`policies/scp-protect-owner.json`](policies/scp-protect-owner.json): an Organizations SCP for when the account sits under an organization the owner controls. It also limits workloads to approved regions.
- `terraform/guardrails`: a multi-region CloudTrail with log file validation, writing to a bucket with Object Lock in COMPLIANCE mode for a year. Not even an administrator can delete those logs early.

**These rules are tested, not just written down.** moto stores these policies but does not evaluate boundaries, KMS key policies or SCPs the way AWS does. So [`tests/test_policies.py`](tests/test_policies.py) renders the exact files Terraform applies and evaluates about 40 requests against them, for example "deploy role tries `iam:UpdateAssumeRolePolicy` on the owner role" or "app decrypts without the SSN context". The evaluator ([`src/takeover/policy_eval.py`](src/takeover/policy_eval.py)) implements only the IAM features these policies use, and raises an error on anything else, so a policy can't pass a test by relying on a feature the evaluator ignores. In a real account the same checks are repeated with the IAM policy simulator and Access Analyzer.

## 4. SSNs: the database only ever holds ciphertext

[`src/takeover/ssn.py`](src/takeover/ssn.py) is envelope encryption at the application layer. Each SSN gets its own AES-256-GCM data key from KMS `GenerateDataKey`, and only the KMS-encrypted data key is stored. So RDS, its snapshots, backups and replicas never contain a readable SSN, and every decrypt is a KMS call recorded in CloudTrail. Both the KMS encryption context and the GCM associated data are bound to the borrower ID, so a sealed SSN copied onto another borrower's row won't decrypt. A logging filter masks anything SSN-shaped (`***-**-6789`), including ITINs. Tests cover the round trip, no plaintext in the stored row, a fresh data key on every seal, rejection of tampered ciphertext, rejection of a sealed SSN moved to another borrower, and log masking.

## 5. Drift

The CI job runs weekly as well as on push. In the lab, someone "temporarily" opens port 5432 to a home IP in the console. `plan -refresh-only -detailed-exitcode` returns 2, and `drift-report` turns the plan JSON into a short note that a reviewer can act on:

```
## `aws_security_group.los_db` (update)
- **ingress**
  - added: `tcp 5432 from 203.0.113.7/32`
```

Attributes AWS changes on its own, such as `latest_restorable_time`, are filtered out, so the report only shows real edits.

## Run it

```bash
pip install -e ".[dev]"
MOTO_IAM_LOAD_MANAGED_POLICIES=true moto_server -p 5000 &
AWS_ENDPOINT_URL=http://127.0.0.1:5000 ./scripts/run_lab.sh     # about 2 minutes
pytest -q                                                        # 73 tests, in-process moto
```

Outputs land in `out/`.

## What this does not prove

- moto evaluates bucket-policy conditions differently from AWS (`aws:SecureTransport`, `aws:PrincipalArn` for assumed roles). The lab therefore applies the state bucket without its policy (`attach_bucket_policy = false`), and the policy is tested by the evaluator instead. In a real account that variable stays `true`.
- Role trust conditions such as MFA on `owner-break-glass` are not enforced by moto.
- The inventory covers the services a typical LOS hosting setup uses: VPC, EC2, RDS, S3, IAM, Secrets Manager and CloudTrail. Route tables, load balancers, Route 53, ACM and backup plans would follow the same pattern: a discovery function, a codegen method and a finding rule each.
- Fixing the findings is out of scope on purpose. Each fix is a separate change with its own plan, review and rollback, never part of the import.
