variable "region" {
  type    = string
  default = "us-east-1"
}

# Only the lab sets this (moto needs path-style S3). Against a real account it
# stays false and the provider uses normal credentials and endpoints.
variable "s3_use_path_style" {
  type    = bool
  default = false
}

provider "aws" {
  region            = var.region
  s3_use_path_style = var.s3_use_path_style
}
