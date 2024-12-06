# Terraform AWS Infrastructure
This project focuses on setting up networking resources such as VPC, Internet Gateway, Route Table, Routes, EC2 instance, Security Groups, RDS, S3, Route43 and Cloudwatch using Terraform for infrastructure setup and teardown. 

## Set up AWS Organization and User
1. Login to your root AWS account and navigate to Organizations.
2. Create an Organization Unit under root.
3. Add an AWS account and login to the newly created account.
4. Navigate to IAM and create a user group with AdministratorAccess permission.
5. Create a user called ```awscli``` and add the user to the user group.
6. Navigate to Security Credentials for the user and create a new access key. Note down the AWS Access Key ID and AWS Secret Access Key.

## Install and configure AWS CLI
1. Install AWS CLI on your machine.
2. Open bash and enter ```aws configure –profile=<profile_name>```
3. Enter your AWS Access Key ID for your profile.
4. Enter your AWS Secret Access Key for your profile.
5. Enter default region name – ```us-east-1```
6. Enter default output format – ```json```

## Terraform/Networking Setup
1. Install Terraform on your machine.
2. Clone the repository.
3. Skip step 4 if you want to set up infrastructure with default values.
4. Create a ```.tfvars``` file in the repository for giving user defined variable values during execution and configure with the following variables - 
    ```
    # environment settings
    region                              = "us-east-1"
    vpc_cidr_block                      = "10.0.0.0/16"
    public_subnet_cidrs                 = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
    private_subnet_cidrs                = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
    availability_zones                  = ["us-east-1a", "us-east-1b", "us-east-1c"]
    public_route_destination_cidr_block = "0.0.0.0/0"
    environment                         = "<your_environment>"
    project_name                        = "<your_project_name>"

    # aws ec2 instance settings
    ami_id              = "<your_custom_ami_id>"
    instance_type       = "t2.micro"
    key_name            = "<your_key_pair_name>"
    instance_name       = "<your_instance_name>"
    security_group_name = "webapp_sg"
    volume_size         = 25
    volume_type         = "gp2"
    service_ports       = [80, 443, 22, 8080]
    protocol            = "tcp"
    ipv4_cidr_blocks    = ["0.0.0.0/0"]
    ipv6_cidr_blocks    = ["::/0"]

    # aws rds settings
    db_identifier        = "<your_custom_identifier>"
    db_engine            = "mysql"
    db_engine_version    = "8.0"
    db_instance_class    = "db.t3.micro"
    db_allocated_storage = 20
    db_name              = "<your_database_name>"
    db_user              = "<your_database_user>"
    db_password          = "<your_database_password>"
    db_port              = 3306

    # route53 settings
    hosted_zone_id = "<your_hosted_zone_id>"
    domain_name    = "<your_domain_name.tld>"
    record_type    = "A"
    record_ttl     = 60
    ```

5. Importing SSL certificates
Import your ssl certificates with the following command - 
```
aws acm import-certificate --certificate fileb://path/file.crt \
                           --private-key fileb://path/file.pem \
                           --certificate-chain fileb://path/file.ca-bundle \
                           --region <your-region>
```

6. Running the VPC, EC2, and RDS instances with S3 bucket - 
   1. Use the correct profile - ```export AWS_PROFILE=<your_profile>```.
   2. Initialize terraform in your repository - ```terraform init```.
   3. Rewrite Terraform configuration files to correct format - ```terraform fmt```.
   4. Validate the configuration files - ```terraform validate```.
   5. Preview the changes to execute - ```terraform plan``` to load default values or  ```-var-file="<file_name.tfvars>"``` to load with user defined values.
   6. Execute the actions to create a VPC and an EC2 instance - ```terraform apply``` to load default values or ```terraform apply -var-file="<file_name.tfvars>"``` to load with user defined values.
   7. Check the created VPC and its configuration on AWS.
   8. Check the created EC2 instance and test it's endpoints.
   9. Destroy the VPC and the instance - ```terraform destroy``` or ```terraform destroy -var-file="<file_name.tfvars>"```.

## Continuous Integration (CI) with GitHub Actions for IaC Repository
GitHub Actions workflow will run terraform fmt (recursively) and terraform validate command for each pull request raised.
A pull request can only be merged if the workflow executes successfully.