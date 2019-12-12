#!/usr/bin/python
import boto3, json, time
from botocore.exceptions import ClientError

session = boto3.session.Session(profile_name='dev', region_name='us-east-1')

env_char    = "d"
account_id  = ""
subnet_id   = ""
key_name    = ""

master_instance_type = 'm4.large'
core_instance_type   = 'm4.large'
task_instance_type   = 'm4.large'
no_of_core_instances = 2
cluster_name         = "Boto3 Test"
release_label        = 'emr-5.26.0'

################################# Bootstrap script copy to S3 ####################################
template = """#!/bin/bash
set -x

sudo yum install  jq -y
TMPFOLDER="/tmp/cloudwatch_tmp/"
## Download and install  cloudwatch agent
sudo mkdir -p $TMPFOLDER && cd $TMPFOLDER
sudo curl https://s3.amazonaws.com/amazoncloudwatch-agent/linux/amd64/latest/AmazonCloudWatchAgent.zip -o $TMPFOLDER/cloudwatch.zip
sudo unzip *.zip
sudo ./install.sh

sudo cat > /tmp/cloudwatch_agent.json << EOF
{
"agent": {
        "metrics_collection_interval": 10,
        "logfile": "/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log"
    },
    "metrics": {
        "namespace": "emr_clusters/bigdataoozie_test",
        "metrics_collected": {
            "disk": {
                "resources": [
                    "/mnt"
                ],
                "measurement": [{
                        "name": "used_percent",
                        "rename": "DISK_USED_PERCENT",
                        "unit": "Gigabytes"
                    },
                    "total",
                    "used"
                ],
                "ignore_file_system_types": [
                    "sysfs", "devtmpfs"
                ],
                "metrics_collection_interval": 1800,
                "append_dimensions": {
                    "InstanceId": "\$${aws:InstanceId}"
                }
            }
        },
        "append_dimensions": {
            "InstanceId": "\$${aws:InstanceId}"
        },
        "aggregation_dimensions": [
            ["ImageId"],
            ["InstanceId", "InstanceType"],
            ["d1"],
            []
        ]
    },
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [{
                        "file_path": "/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log",
                        "log_group_name": "/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log",
                        "timezone": "UTC"
                    }
                ]
            }
        },
        "log_stream_name": "{instance_id}, {hostname}, {ip_address}"
    }
}

EOF

##### fetching and Updating the configs
sudo cp /tmp/cloudwatch_agent.json  /etc/cloudwatch_agent.json
sudo  /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/etc/cloudwatch_agent.json
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a start -m ec2 -c file:/etc/cloudwatch_agent.json
#sudo echo "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a start -m ec2 -c file:/etc/cloudwatch_agent.json" >> /etc/rc.local
sudo sh -c  "echo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a start -m ec2 -c file:/etc/cloudwatch_agent.json >> /etc/rc.local"
"""
f = open("/tmp/boto3_emr_bootstrap_script.sh", "w+")
f.write(template)

bucket = '{}-emr-resources'.format(env_char),
s3 = boto3.resource('s3')
s3.meta.client.upload_file('/tmp/boto3_emr_bootstrap_script.sh', '{}-emr-resources'.format(env_char), 'emr/bootstrap-actions/boto3_emr_bootstrap_script.sh')

################################# IAM ############################################################
iam = session.client('iam')

path='/'
role_name   = 'BOTO3-Test-emr-service-role'
description = 'BOTO3 service role'

trust_policy = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "elasticmapreduce.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

try:
   srv_role_response = iam.create_role(
        Path                     = path,
        RoleName                 = role_name,
        AssumeRolePolicyDocument = json.dumps(trust_policy),
        Description              = description,
        MaxSessionDuration       = 3600,
   )

   print(srv_role_response)
   srv_role_name = str(srv_role_response['Role']['RoleName'])   
except Exception as e:
   print(e)

#####################################
path='/'
role_name   = 'BOTO3-Test-emr-instance-role'
description = 'BOTO3 instance role'

trust_policy = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

try:
    inst_role_response = iam.create_role(
        Path                     = path,
        RoleName                 = role_name,
        AssumeRolePolicyDocument = json.dumps(trust_policy),
        Description              = description,
        MaxSessionDuration       = 3600,
    )

    print(inst_role_response)
    inst_role_name = str(inst_role_response['Role']['RoleName'])
    inst_role_arn  = str(inst_role_response['Role']['Arn'])
except Exception as e:
    print(e)
###################################### KMS ##################################

time.sleep(30)

###################################### KMS ##################################
kms = session.client('kms')

key_response = kms.create_key (
  Description = '{}-BOTO3-Test-emrkms'.format(env_char),
)

print(key_response) , "\n"

key_id  = str(key_response['KeyMetadata']['KeyId'])
key_arn = str(key_response['KeyMetadata']['Arn'])

key_grant = kms.create_grant (
  Name             = '{}-BOTO3-Test-emrkms'.format(env_char),
  KeyId            = key_id,
  GranteePrincipal = inst_role_arn,
  Operations       = ["Encrypt", "Decrypt", "ReEncryptFrom", "ReEncryptTo", "GenerateDataKey", "DescribeKey"]
)

#############################################################
my_managed_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Resource": "*",
            "Action": [
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:CancelSpotInstanceRequests",
                "ec2:CreateNetworkInterface",
                "ec2:CreateSecurityGroup",
                "ec2:CreateTags",
                "ec2:DeleteNetworkInterface",
                "ec2:DeleteSecurityGroup",
                "ec2:DeleteTags",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeDhcpOptions",
                "ec2:DescribeImages",
                "ec2:DescribeInstanceStatus",
                "ec2:DescribeInstances",
                "ec2:DescribeKeyPairs",
                "ec2:DescribeNetworkAcls",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribePrefixLists",
                "ec2:DescribeRouteTables",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSpotInstanceRequests",
                "ec2:DescribeSpotPriceHistory",
                "ec2:DescribeSubnets",
                "ec2:DescribeTags",
                "ec2:DescribeVpcAttribute",
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeVpcEndpointServices",
                "ec2:DescribeVpcs",
                "ec2:DetachNetworkInterface",
                "ec2:ModifyImageAttribute",
                "ec2:ModifyInstanceAttribute",
                "ec2:RequestSpotInstances",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:RunInstances",
                "ec2:TerminateInstances",
                "ec2:DeleteVolume",
                "ec2:DescribeVolumeStatus",
                "ec2:DescribeVolumes",
                "ec2:DetachVolume",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:ListInstanceProfiles",
                "iam:ListRolePolicies",
                "iam:PassRole",
                "s3:CreateBucket",
                "s3:Get*",
                "s3:List*",
                "sdb:BatchPutAttributes",
                "sdb:Select",
                "sqs:CreateQueue",
                "sqs:Delete*",
                "sqs:GetQueue*",
                "sqs:PurgeQueue",
                "sqs:ReceiveMessage",
                "cloudwatch:PutMetricAlarm",
                "cloudwatch:DescribeAlarms",
                "cloudwatch:DeleteAlarms",
                "application-autoscaling:RegisterScalableTarget",
                "application-autoscaling:DeregisterScalableTarget",
                "application-autoscaling:PutScalingPolicy",
                "application-autoscaling:DeleteScalingPolicy",
                "application-autoscaling:Describe*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "arn:aws:iam::*:role/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot*",
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "spot.amazonaws.com"
                }
            }
        },
        {
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyWithoutPlaintext",
                "kms:DescribeKey",
                "kms:ReEncrypt",
                "kms:CreateGrant"
            ],
            "Effect": "Allow",
            "Resource": key_arn
        }
    ]
}

srv_pol_response = iam.create_policy(
  PolicyName     = 'BOTO3-Test-emrservice-policy',
  PolicyDocument = json.dumps(my_managed_policy)
)
print(srv_pol_response)
srv_pol_arn = str(srv_pol_response['Policy']['Arn'])

iam.attach_role_policy(
    PolicyArn = srv_pol_arn,
    RoleName  = srv_role_name
)

##########################################
instance_managed_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Resource": "*",
            "Action": [
                "cloudwatch:*",
                "ec2:Describe*",
                "elasticmapreduce:Describe*",
                "elasticmapreduce:ListBootstrapActions",
                "elasticmapreduce:ListClusters",
                "elasticmapreduce:ListInstanceGroups",
                "elasticmapreduce:ListInstances",
                "elasticmapreduce:ListSteps",
                "s3:ListAllBuckets"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketLocation",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::{}-datalake-resources".format(env_char),
                "arn:aws:s3:::{}-input*".format(env_char),
                "arn:aws:s3:::{}-output*".format(env_char)
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:PutObject",
                "s3:GetObject",
                "s3:GetBucketLocation",
                "s3:DeleteObject",
                "s3:GetObjectAcl",
                "s3:GetObjectVersion"
            ],
            "Resource": [
                "arn:aws:s3:::{}-emr-resources".format(env_char),
                "arn:aws:s3:::{}-emr-resources/*".format(env_char),
                "arn:aws:s3:::{}-input*".format(env_char),
                "arn:aws:s3:::{}-input/*".format(env_char),
                "arn:aws:s3:::{}-output*".format(env_char),
                "arn:aws:s3:::{}-output/*".format(env_char),
                "arn:aws:s3:::elasticmapreduce*",
                "arn:aws:s3:::elasticmapreduce/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ],
            "Resource": [
                "arn:aws:logs:*:*:*"
            ]
        },
        {
            "Effect": "Deny",
            "Action": [
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::{}-emr-resources/logs/*".format(env_char)
            ]
        },
        {
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Effect": "Allow",
            "Resource": key_arn
        }
    ]
}

inst_pol_response = iam.create_policy(
  PolicyName     = 'BOTO3-Test-emr-instance-policy',
  PolicyDocument = json.dumps(instance_managed_policy)
)
print(inst_pol_response)
inst_pol_arn = str(inst_pol_response['Policy']['Arn'])

iam.attach_role_policy(
    PolicyArn = inst_pol_arn,
    RoleName  = inst_role_name
)

########################################

inst_prof_response = iam.create_instance_profile(
    InstanceProfileName = 'BOTO3-Test-emr-instance-profile'
)

inst_pro_name = str(inst_prof_response['InstanceProfile']['InstanceProfileName'])

role_to_inst_response = iam.add_role_to_instance_profile(
    InstanceProfileName = inst_pro_name,
    RoleName            = inst_role_name
)
print(role_to_inst_response)

########################################
path='/'
role_name   = 'BOTO3-Test-emr-autoscaling-role'
description = 'BOTO3 autoscaling role'

trust_policy = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": [
           "application-autoscaling.amazonaws.com",
           "elasticmapreduce.amazonaws.com"
         ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

try:
    autoscl_role_response = iam.create_role(
        Path                     = path,
        RoleName                 = role_name,
        AssumeRolePolicyDocument = json.dumps(trust_policy),
        Description              = description,
        MaxSessionDuration       = 3600,
    )

    print(autoscl_role_response)
    autoscl_role_name = str(autoscl_role_response['Role']['RoleName'])
except Exception as e:
    print(e)

##################################
autoscaling_managed_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:DescribeAlarms",
                "elasticmapreduce:ListInstanceGroups",
                "elasticmapreduce:ModifyInstanceGroups"
             ],
            "Resource": "*"
        }
    ]
}

autoscl_pol_response = iam.create_policy(
  PolicyName     = 'BOTO3-Test-emr-autoscaling-policy',
  PolicyDocument = json.dumps(autoscaling_managed_policy)
)
print(autoscl_pol_response)
autoscl_pol_arn = str(autoscl_pol_response['Policy']['Arn'])

iam.attach_role_policy(
    PolicyArn = autoscl_pol_arn,
    RoleName  = autoscl_role_name
)

################################# Security Groups ############################################################
ec2     = session.client('ec2')

#response = ec2.describe_vpcs()
vpc_id = ""

try:
    response = ec2.create_security_group(GroupName='BOTO3_emr_master',
                                         Description='sg for emr master node',
                                         VpcId=vpc_id)
    security_group_id = response['GroupId']
    print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id))
except ClientError as e:
    print(e)
#######################
try:
    response = ec2.create_security_group(GroupName='BOTO3_emr_core_1',
                                         Description='sg for emr core nodes',
                                         VpcId=vpc_id)
    core_security_group_id = response['GroupId']
    print('Security Group Created %s in vpc %s.' % (core_security_group_id, vpc_id))
except ClientError as e:
    print(e)
########################
try:
    response = ec2.create_security_group(GroupName='BOTO3_emr_service',
                                         Description='sg for emr service',
                                         VpcId=vpc_id)
    service_security_group_id = response['GroupId']
    print('Security Group Created %s in vpc %s.' % (service_security_group_id, vpc_id))
except ClientError as e:
    print(e)
########################
try:
    data = ec2.authorize_security_group_ingress(
        GroupId = security_group_id,
        IpPermissions = [
          {
           'IpProtocol'    : 'tcp',
           'FromPort'      : 8443,
           'ToPort'        : 8443,
           'IpRanges'      : [
               {
                   "CidrIp" : ""
               },
               {
                   "CidrIp" : ""
               }
           ],
          },
          {
           'IpProtocol'    : 'tcp',
           'FromPort'      : 22,
           'ToPort'        : 22,
           'IpRanges'      : [
               {
                   "CidrIp" : '0.0.0.0/0'
               },
               {
                   "CidrIp" : ""
               }
           ],
          },
          {
           'IpProtocol'    : '-1',
           'FromPort'      : 0,
           'ToPort'        : 0,
           'IpRanges'      : [{"CidrIp" : '0.0.0.0/0'}]
          }
    ])
    data = ec2.authorize_security_group_egress(
        GroupId = security_group_id,
        IpPermissions = [
          {
           'IpProtocol'    : '-1',
           'FromPort'      : 0,
           'ToPort'        : 0,
           'IpRanges'      : [{"CidrIp" : '0.0.0.0/0'}]
          }
    ])
    print('SG Successfully Set %s' % data)
except ClientError as e:
    print(e)
##########################
try:
    data = ec2.authorize_security_group_ingress(
        GroupId = core_security_group_id,
        IpPermissions = [
          {
           'IpProtocol'    : 'tcp',
           'FromPort'      : 22,
           'ToPort'        : 22,
           'IpRanges'      : [
               {
                   "CidrIp" : '0.0.0.0/0'
               },
               {
                   "CidrIp" : ""
               }
           ],
          },
          {
           'IpProtocol'    : '-1',
           'FromPort'      : 0,
           'ToPort'        : 0,
           "UserIdGroupPairs": [
               {
                  "GroupId": security_group_id
               }
            ]
          }
    ])
    data = ec2.authorize_security_group_egress(
        GroupId = core_security_group_id,
        IpPermissions = [
          {
           'IpProtocol'    : '-1',
           'FromPort'      : 0,
           'ToPort'        : 0,
           'IpRanges'      : [{"CidrIp" : '0.0.0.0/0'}]
          }
    ])
    print('SG Successfully Set %s' % data)
except ClientError as e:
    print(e)
#################################
try:
    data = ec2.authorize_security_group_egress(
        GroupId = service_security_group_id,
        IpPermissions = [
          {
           'IpProtocol'    : 'tcp',
           'FromPort'      : 8443,
           'ToPort'        : 8443,
            "UserIdGroupPairs": [
                {
                 "GroupId": security_group_id
                },
                {
                 "GroupId": core_security_group_id
                }
            ]
          }
        ]
    )
    print('SG Successfully Set %s' % data)
except ClientError as e:
    print(e)
####################################
try:
     data = ec2.authorize_security_group_ingress(
         GroupId = core_security_group_id,
         IpPermissions = [
           {
            'IpProtocol'    : 'tcp',
            'FromPort'      : 8443,
            'ToPort'        : 8443,
             "UserIdGroupPairs": [
                 {
                  "GroupId": service_security_group_id
                 }
             ],
           },
     ])
     print('SG Successfully Set %s' % data)
except ClientError as e:
     print(e)
##################################
try:
     data = ec2.authorize_security_group_ingress(
         GroupId = security_group_id,
         IpPermissions = [
           {
            'IpProtocol'    : 'tcp',
            'FromPort'      : 8443,
            'ToPort'        : 8443,
             "UserIdGroupPairs": [
                 {
                  "GroupId": service_security_group_id
                 },
                 {
                  "GroupId": core_security_group_id
                 }
             ]
           },
           {
            'IpProtocol'    : '-1',
            'FromPort'      : 0,
            'ToPort'        : 0,
             "UserIdGroupPairs": [
                 {
                  "GroupId": service_security_group_id
                 },
                 {
                  "GroupId": core_security_group_id
                 }
             ]
           }
     ])
     print('SG Successfully Set %s' % data)
except ClientError as e:
     print(e)
################################# EMR CREATION ############################################################

time.sleep(60)

################################# EMR CREATION ############################################################
emrClient = session.client('emr')

masterInstanceType = master_instance_type
coreInstanceType   = core_instance_type
taskInstanceType   = task_instance_type
coreInstanceNum    = no_of_core_instances
clusterName        = cluster_name

logUri = 's3://{}-emr-resources/emr/emr_logs/'.format(env_char)
releaseLabel = release_label

instances = {
    'Ec2KeyName': key_name,
    'Ec2SubnetId': subnet_id,
    'ServiceAccessSecurityGroup': service_security_group_id,
    'EmrManagedMasterSecurityGroup': security_group_id,
    'EmrManagedSlaveSecurityGroup': core_security_group_id,
    'KeepJobFlowAliveWhenNoSteps': True,
    'TerminationProtected': False,
    'InstanceGroups': [{
        'InstanceRole': 'MASTER',
        "InstanceCount": 1,
            "InstanceType": masterInstanceType,
            "Market": "ON_DEMAND",
            "Name": "Master"
        }, 
        {
            'InstanceRole': 'CORE',
            "InstanceCount": coreInstanceNum,
            "InstanceType": coreInstanceType,
            "Market": "ON_DEMAND",
            "Name": "Core",
            "EbsConfiguration" : {
                "EbsBlockDeviceConfigs" : [
                    {
                       'VolumeSpecification': {
                           'VolumeType': 'gp2',
                           'SizeInGB': 64
                        },
                        'VolumesPerInstance': 1
                    }
                ]
            }         
        }            
    ]
}

Tags=[
   {
     'Name': 'Name',
     'Value': 'BOTO3 Test'
   },
   {
     'Name': 'Project',
     'Value': 'EMR Using BOTO3'
   }
],

securityConfig = {
  "EncryptionConfiguration": {
    "InTransitEncryptionConfiguration":{
      "TLSCertificateConfiguration":{
        "CertificateProviderType":"PEM",
        "S3Object":'s3://{}-emr-resources/emr/{}-EMR/certs.zip'.format(env_char, env_char)
      }
    },
    "AtRestEncryptionConfiguration": {
      "S3EncryptionConfiguration": {
        "EncryptionMode": "SSE-S3"
      },
      "LocalDiskEncryptionConfiguration": {
        "EnableEbsEncryption" : True,
        "EncryptionKeyProviderType": "AwsKms",
        "AwsKmsKey": key_id
      }
    },
    "EnableInTransitEncryption": True,
    "EnableAtRestEncryption": True
  }
}
security_config_json = json.dumps(securityConfig)

security_config_response = emrClient.create_security_configuration (
   Name                  = '{}-BOTO3-emr-sconfig'.format(env_char),
   SecurityConfiguration = security_config_json
)

security_config_name = str(security_config_response['Name'])

bootstrapActions = [
  {
    'Name': 'Cloudwatch log agent installation',
    'ScriptBootstrapAction': {
        'Path' : 's3://{}-emr-resources/emr/bootstrap-actions/boto3_emr_bootstrap.sh'.format(env_char),
        'Args' : [
            'instance.isMaster=true', 
            'echo running on master node'
         ]
    }
  }
]

emr_response = emrClient.run_job_flow(
    Name                  = clusterName,
    ReleaseLabel          = releaseLabel,
    Instances             = instances,
    AutoScalingRole       = autoscl_role_name,
    BootstrapActions      = bootstrapActions,
    VisibleToAllUsers     = True,
    JobFlowRole           = inst_pro_name,
    ServiceRole           = srv_role_name,
    SecurityConfiguration = security_config_name
)

######################################## Cloudwatch Alarms ##########################################################
cloudwatch = session.client('cloudwatch')

cloudwatch.put_metric_alarm(
    AlarmName          = 'BOTO3_mnt',
    ComparisonOperator = 'GreaterThanThreshold',
    EvaluationPeriods  = 2,
    MetricName         = 'DISK_USED_PERCENT',
    Namespace          = 'emr_clusters/Boto3 Test',
    Period             = 1800,
    Statistic          = 'Average',
    Threshold          = 75,
    ActionsEnabled     = False,
    AlarmDescription   = 'This metric monitors /mnt free space',
    Dimensions         = [],
    Unit               = 'Gigabytes',
    DatapointsToAlarm  = 2,
    AlarmActions       = ['arn:aws:sns:<region>:<account_id>:<sns_topic_name>']
)
