output "private_ca_arn" {
  value = aws_acmpca_certificate_authority.client_ca.arn
}

# PEM certificate of the Private CA, for the ImportKey step in the README.
output "private_ca_certificate_pem" {
  value = aws_acmpca_certificate.client_ca.certificate
}

# Everything backend/.env needs except APC_CA_PUBLIC_KEY_ARN, which comes
# from the ImportKey step.
output "backend_env" {
  value = <<-EOT
    AWS_REGION=${var.region}
    BACKEND_ADDR=127.0.0.1:8080
    ALLOWED_ORIGINS=http://localhost:8081,http://127.0.0.1:8081
    PRIVATE_CA_ARN=${aws_acmpca_certificate_authority.client_ca.arn}
    APC_KEY_AGREEMENT_KEY_ARN=${aws_paymentcryptography_key.key_agreement.arn}
    APC_PEK_ARN=${aws_paymentcryptography_key.pek.arn}
    APC_PVK_ARN=${aws_paymentcryptography_key.pvk.arn}
    APC_PVK_INDEX=1
    PIN_VERIFIER_TABLE_NAME=${aws_dynamodb_table.verifiers.name}
    LOG_LEVEL=info
    DEMO_LOG_SENSITIVE_VALUES=false
  EOT
}

# For the KMS statement in the README's backend IAM policy.
output "verifier_table_kms_key_arn" {
  value = aws_kms_key.verifiers.arn
}

output "region" {
  value = var.region
}
