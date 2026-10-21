# AWS resources for the remote PIN selection demo. The numbered sections follow
# the trust setup in the blog post. Section 3, importing the CA certificate
# into AWS Payment Cryptography, has no Terraform resource: the README runs it
# with the AWS CLI after `terraform apply`.

data "aws_partition" "current" {}

# ---------------------------------------------------------------------------
# 1. AWS Private CA that certifies the app's ephemeral key
# ---------------------------------------------------------------------------

# SHORT_LIVED_CERTIFICATE mode caps issued certificates at 7 days, which is
# all this flow needs (the backend asks for 15 minutes). P-256 matches the
# rest of the profile.
resource "aws_acmpca_certificate_authority" "client_ca" {
  type       = "ROOT"
  usage_mode = "SHORT_LIVED_CERTIFICATE"

  certificate_authority_configuration {
    key_algorithm     = "EC_prime256v1"
    signing_algorithm = "SHA256WITHECDSA"

    subject {
      common_name = "Remote PIN Demo Client CA"
    }
  }

  # Shortest restore window after `terraform destroy`.
  permanent_deletion_time_in_days = 7
}

# A root CA activates by signing its own CSR and installing the result.
resource "aws_acmpca_certificate" "client_ca" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.client_ca.arn
  certificate_signing_request = aws_acmpca_certificate_authority.client_ca.certificate_signing_request
  signing_algorithm           = "SHA256WITHECDSA"
  template_arn                = "arn:${data.aws_partition.current.partition}:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "YEARS"
    value = 10
  }
}

resource "aws_acmpca_certificate_authority_certificate" "client_ca" {
  certificate_authority_arn = aws_acmpca_certificate_authority.client_ca.arn
  certificate               = aws_acmpca_certificate.client_ca.certificate
  certificate_chain         = aws_acmpca_certificate.client_ca.certificate_chain
}

# ---------------------------------------------------------------------------
# 2. AWS Payment Cryptography keys
# ---------------------------------------------------------------------------

# ECDH key-agreement key: the service's side of ECDH with the app. The backend
# returns its public certificate to the app.
resource "aws_paymentcryptography_key" "key_agreement" {
  exportable              = true
  deletion_window_in_days = 3

  key_attributes {
    key_algorithm = "ECC_NIST_P256"
    key_class     = "ASYMMETRIC_KEY_PAIR"
    key_usage     = "TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT"

    key_modes_of_use {
      derive_key = true
    }
  }
}

# Outgoing PIN encryption key (PEK): the key the processor expects PIN blocks
# under. In production it comes from a key exchange with the processor.
resource "aws_paymentcryptography_key" "pek" {
  exportable              = true
  deletion_window_in_days = 3

  key_attributes {
    key_algorithm = "TDES_2KEY"
    key_class     = "SYMMETRIC_KEY"
    key_usage     = "TR31_P0_PIN_ENCRYPTION_KEY"

    key_modes_of_use {
      encrypt = true
      decrypt = true
      wrap    = true
      unwrap  = true
    }
  }
}

# PROCESSOR SIDE (demo stand-in): Visa PIN verification key for PVV
# generation and verification.
resource "aws_paymentcryptography_key" "pvk" {
  exportable              = true
  deletion_window_in_days = 3

  key_attributes {
    key_algorithm = "TDES_2KEY"
    key_class     = "SYMMETRIC_KEY"
    key_usage     = "TR31_V2_VISA_PIN_VERIFICATION_KEY"

    key_modes_of_use {
      generate = true
      verify   = true
    }
  }
}

resource "aws_paymentcryptography_key_alias" "key_agreement" {
  alias_name = "alias/${var.name}-key-agreement"
  key_arn    = aws_paymentcryptography_key.key_agreement.arn
}

resource "aws_paymentcryptography_key_alias" "pek" {
  alias_name = "alias/${var.name}-pek"
  key_arn    = aws_paymentcryptography_key.pek.arn
}

resource "aws_paymentcryptography_key_alias" "pvk" {
  alias_name = "alias/${var.name}-pvk"
  key_arn    = aws_paymentcryptography_key.pvk.arn
}

# ---------------------------------------------------------------------------
# PROCESSOR SIDE (demo stand-in): PVV verifier records
# ---------------------------------------------------------------------------

# Customer managed key for the verifier table, so access to PVV records can be
# controlled and audited through the key policy and CloudTrail.
resource "aws_kms_key" "verifiers" {
  description             = "${var.name} verifier table encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "verifiers" {
  name          = "alias/${var.name}-verifiers"
  target_key_id = aws_kms_key.verifiers.key_id
}

# One item per PAN. Synthetic PANs only.
resource "aws_dynamodb_table" "verifiers" {
  name         = "${var.name}-verifiers"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pan"

  attribute {
    name = "pan"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.verifiers.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}
