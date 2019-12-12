This Python code uses boto3 libraries to create EMR Cluster on AWS.

We need several AWS services to create an EMR, like Bootstrap script, IAM Roles and Policies,
Instance profile, Security groups, kms key to encrypt EBS Volumes, KMS key grants, Secuirty config for EMR
and finally EMR Creation and creating cloudwatch alarms. This code creates all the required services.

We have to define the variables that are left empty, like account_id, vpc_id, subnet_id, region_name etc

we can run the script by ``./emr_creation.py`` or ``python emr_creation.py``
