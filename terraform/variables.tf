variable "region" {
  description = "Region for every resource. It must offer AWS Payment Cryptography."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Prefix for resource names and aliases, and the Project tag value."
  type        = string
  default     = "remote-pin-demo"
}
