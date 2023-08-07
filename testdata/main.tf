variable "ingress_cidr_blocks" {
  type        = list(string)
  description = "Source IP addresses for the security group ingress rule."

  default = [
    "0.0.0.0/0",
  ]
}

provider "aws" {}

resource "aws_vpc" "vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "Active Directory"
  }
}

resource "aws_route_table" "rtb" {
  vpc_id = aws_vpc.vpc.id
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
}

resource "aws_route" "igw" {
  route_table_id         = aws_route_table.rtb.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "subnet" {
  count             = min(length(data.aws_availability_zones.available.names), 2)
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet("10.0.0.0/16", 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
}

resource "aws_route_table_association" "rtb" {
  for_each       = toset(aws_subnet.subnet[*].id)
  subnet_id      = each.value
  route_table_id = aws_route_table.rtb.id
}

resource "random_password" "password" {
  length = 16
}

resource "aws_directory_service_directory" "ad" {
  name     = "example.com"
  password = random_password.password.result
  size     = "Small"

  vpc_settings {
    vpc_id     = aws_vpc.vpc.id
    subnet_ids = aws_subnet.subnet[*].id
  }
}

resource "aws_vpc_dhcp_options" "options" {
  domain_name         = "example.com"
  domain_name_servers = aws_directory_service_directory.ad.dns_ip_addresses
}

resource "aws_vpc_dhcp_options_association" "vpc" {
  vpc_id          = aws_vpc.vpc.id
  dhcp_options_id = aws_vpc_dhcp_options.options.id
}

data "aws_ami" "windows" {
  most_recent = true
  name_regex  = "Windows_Server-2022-English-Full-Base-"

  owners = [
    "801119661308",
  ]
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect = "Allow"

    principals {
      type = "Service"

      identifiers = [
        "ec2.amazonaws.com",
      ]
    }

    actions = [
      "sts:AssumeRole",
    ]
  }
}

resource "aws_iam_role" "role" {
  name               = "WindowsRole"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMDirectoryServiceAccess",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
  ]
}

resource "aws_iam_instance_profile" "role" {
  name_prefix = "role-"
  role        = aws_iam_role.role.name
}

resource "aws_key_pair" "key" {
  key_name   = "windows"
  public_key = file("${path.module}/id_rsa.pub")
}

resource "aws_security_group" "sg" {
  name_prefix = "windows-"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidr_blocks
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidr_blocks
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"

    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }
}

resource "aws_instance" "windows" {
  ami                         = data.aws_ami.windows.id
  associate_public_ip_address = true
  get_password_data           = true
  iam_instance_profile        = aws_iam_instance_profile.role.name
  instance_type               = "t3.micro"
  key_name                    = aws_key_pair.key.key_name
  subnet_id                   = aws_subnet.subnet[0].id

  vpc_security_group_ids = [
    aws_security_group.sg.id,
  ]

  depends_on = [
    aws_internet_gateway.igw,
  ]
}
#
resource "aws_ssm_document" "ad_join_domain" {
  name          = "ad-join-domain"
  document_type = "Command"

  content = jsonencode(
    {
      "schemaVersion" = "2.2"
      "description"   = "aws:domainJoin"
      "mainSteps" = [
        {
          "action" = "aws:domainJoin",
          "name"   = "domainJoin",
          "inputs" = {
            "directoryId" : aws_directory_service_directory.ad.id
            "directoryName" : aws_directory_service_directory.ad.name
            "dnsIpAddresses" : sort(aws_directory_service_directory.ad.dns_ip_addresses)
          }
        }
      ]
    }
  )
}

resource "aws_ssm_association" "example" {
  name = aws_ssm_document.ad_join_domain.name

  targets {
    key = "InstanceIds"

    values = [
      aws_instance.windows.id,
    ]
  }
}

output "instance" {
  value = aws_instance.windows
}

output "password" {
  value     = random_password.password.result
  sensitive = true
}
