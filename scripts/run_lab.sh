#!/usr/bin/env bash
# The whole takeover, end to end, against a local moto server:
#
#   1. seed        the previous engineer's hand-built environment (no Terraform)
#   2. inventory   read-only discovery first -> inventory, findings, report, diagram
#   3. bootstrap   owner creates the state bucket, deploy role and admin boundary
#   4. guardrails  owner creates the SSN key and the Object Lock audit trail
#   5. codegen     inventory -> Terraform code + import blocks
#   6. import      plan must be imports only; apply; re-plan must be empty
#   7. drift       someone edits a security group in the console; the
#                  scheduled drift check catches it and names the change
#   8. inventory   again, to show what the guardrails changed
#
# Needs: a moto server at $AWS_ENDPOINT_URL, terraform or tofu on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/out}"
TF="${TF:-$(command -v terraform || command -v tofu)}"
export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://127.0.0.1:5000}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export TF_VAR_s3_use_path_style=true TF_IN_AUTOMATION=1
ACCOUNT=123456789012
STATE_BUCKET=acme-tfstate

step() { printf '\n==> %s\n' "$*"; }
tf() { "$TF" -chdir="$1" "$2" -input=false -no-color "${@:3}"; }
tfjson() { "$TF" -chdir="$1" show -json -no-color ${2:+"$2"}; }
as_owner() {
  export AWS_ACCESS_KEY_ID=owner AWS_SECRET_ACCESS_KEY=owner
  unset AWS_SESSION_TOKEN
}
as_role() {
  as_owner
  eval "$(python3 -m takeover assume "arn:aws:iam::$ACCOUNT:role/$1")"
}

rm -rf "$OUT" && mkdir -p "$OUT"
cp -r "$ROOT/terraform" "$ROOT/policies" "$OUT/"
# Lab only: pin the AWS provider to the version this lab is tested with. Newer
# releases read S3 bucket tags through S3 Control, which prefixes the endpoint
# host with the account ID (123456789012.127.0.0.1); a local moto endpoint
# can't answer that. Against a real account the repo's "~> 6.20" stands.
sed -i 's/version = "~> 6.20"/version = "6.20.0"/' "$OUT"/terraform/*/*.tf
ENV="$OUT/terraform/environment"
curl -fsS -X POST "$AWS_ENDPOINT_URL/moto-api/reset" >/dev/null
as_owner

step "1. seed: the inherited, hand-built environment"
python3 -m takeover seed > "$OUT/seed.json"

step "2. inventory (read-only, before any change)"
python3 -m takeover inventory --out "$OUT" --name before --title "Takeover report: week one, read-only"

step "3. bootstrap (as owner): state bucket, deploy role, admin boundary"
export TF_VAR_state_bucket="$STATE_BUCKET" TF_VAR_attach_bucket_policy=false
export TF_VAR_owner_principal_arn="arn:aws:iam::$ACCOUNT:user/owner"
export TF_VAR_deploy_trusted_arns="[\"arn:aws:iam::$ACCOUNT:root\"]"
tf "$OUT/terraform/bootstrap" init >/dev/null
tf "$OUT/terraform/bootstrap" apply -auto-approve | grep -E "^Apply complete"

step "4. guardrails (as owner-break-glass): SSN key, CloudTrail with Object Lock"
as_role owner-break-glass
export TF_VAR_trail_bucket=acme-audit-trail
tf "$OUT/terraform/guardrails" init >/dev/null
tf "$OUT/terraform/guardrails" apply -auto-approve | grep -E "^Apply complete"

step "5. codegen: week-one inventory -> Terraform + import blocks"
python3 -m takeover codegen "$OUT/before-inventory.json" "$ENV"
"$TF" fmt "$ENV" >/dev/null
printf 'bucket         = "%s"\nkey            = "los-prod/terraform.tfstate"\nregion         = "%s"\nuse_path_style = true\n' \
  "$STATE_BUCKET" "$AWS_DEFAULT_REGION" > "$ENV/backend.hcl"

step "6. import (as terraform-deploy): plan must be imports only"
as_role terraform-deploy
tf "$ENV" init -backend-config=backend.hcl >/dev/null
tf "$ENV" plan -out=import.tfplan > "$OUT/import-plan.txt"
tfjson "$ENV" import.tfplan > "$OUT/import-plan.json"
python3 -m takeover check-import "$OUT/import-plan.json"
tf "$ENV" apply import.tfplan | grep -E "^Apply complete"
rm "$ENV/imports.tf" "$ENV/import.tfplan" # imports are one-shot; the code now owns these resources
set +e
tf "$ENV" plan -detailed-exitcode > "$OUT/post-import-plan.txt"
code=$?
set -e
if [ "$code" -ne 0 ]; then
  echo "post-import plan is not empty (exit $code):"
  cat "$OUT/post-import-plan.txt"
  exit 1
fi
echo "post-import plan: no changes. The code matches the account."

step "7. drift: an out-of-band console change, caught by the scheduled check"
python3 -m takeover simulate-drift
set +e
tf "$ENV" plan -refresh-only -detailed-exitcode -out=drift.tfplan > "$OUT/drift-plan.txt"
code=$?
set -e
if [ "$code" -ne 2 ]; then
  echo "expected drift (exit 2), got $code"
  cat "$OUT/drift-plan.txt"
  exit 1
fi
tfjson "$ENV" drift.tfplan > "$OUT/drift-plan.json"
python3 -m takeover drift-report "$OUT/drift-plan.json" | tee "$OUT/drift.md"

step "8. inventory again (read-only), with Terraform state for coverage"
tfjson "$ENV" "" > "$OUT/state-environment.json"
as_owner
tfjson "$OUT/terraform/bootstrap" "" > "$OUT/state-bootstrap.json"
tfjson "$OUT/terraform/guardrails" "" > "$OUT/state-guardrails.json"
python3 -m takeover inventory --out "$OUT" --name after --title "Takeover report: after import and guardrails" \
  --tf-state "$OUT/state-environment.json" --tf-state "$OUT/state-bootstrap.json" --tf-state "$OUT/state-guardrails.json"
sed -n '5,12p' "$OUT/after-report.md"

step "done: artifacts in $OUT"
