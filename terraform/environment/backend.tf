# State lives in the bucket created by terraform/bootstrap: versioned,
# KMS-encrypted, public access blocked, TLS-only, with S3-native locking.
# Bucket, key and region come from a backend config file (backend.hcl).
terraform {
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}
