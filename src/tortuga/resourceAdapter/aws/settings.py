# Copyright 2008-2018 Univa Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from boto3.session import Session

from tortuga.resourceAdapterConfiguration import settings


GROUP_INSTANCES = {
    'group': 'Instances',
    'group_order': 0
}
GROUP_AUTHENTICATION = {
    'group': 'Authentication',
    'group_order': 1
}
GROUP_DNS = {
    'group': 'DNS',
    'group_order': 2
}
GROUP_NETWORKING = {
    'group': 'Networking',
    'group_order': 3
}
GROUP_SPOT = {
    'group': 'Spot',
    'group_order': 4
}
GROUP_API = {
    'group': 'API',
    'group_order': 5
}
GROUP_COST = {
    'group': 'Cost Sync',
    'group_order': 9
}

SETTINGS = {
    #
    # Instances
    #
    'tags': settings.TagListSetting(
        display_name='Tags',
        key_validation_regex='^(?!aws:).{0,127}',
        value_validation_regex='.{0,256}',
        description='A comma-separated list of tags in the form of '
                    'key=value',
        **GROUP_INSTANCES
    ),
    'instancetype': settings.StringSetting(
        display_name='Instance type',
        description='AWS compute node instance type',
        required=True,
        **GROUP_INSTANCES
    ),
    'ami': settings.StringSetting(
        display_name='AMI',
        description='AMI ID to use for launching node instances',
        required=True,
        **GROUP_INSTANCES
    ),
    'block_device_map': settings.StringSetting(
        display_name='Block device map',
        description='Used to define block devices (virtual hard drives)',
        **GROUP_INSTANCES
    ),
    'cloud_init_script_template': settings.FileSetting(
        display_name='cloud-init script template',
        description='Path to cloud-init script template',
        base_path='/opt/tortuga/config/',
        **GROUP_INSTANCES
    ),
    'user_data_script_template': settings.FileSetting(
        display_name='User data script template',
        description='Path to user data template script',
        base_path='/opt/tortuga/config/',
        **GROUP_INSTANCES
    ),
    'vcpus': settings.IntegerSetting(
        display_name='Number of VCPUs',
        description='Override automatically detected virtual CPU count',
        **GROUP_INSTANCES
    ),
    'monitoring_enabled': settings.BooleanSetting(
        display_name='Enable detailed CloudWatch monitoring',
        **GROUP_INSTANCES
    ),
    'ebs_optimized': settings.BooleanSetting(
        display_name='Enable EBS optimization for additional disk'
                     ' throughput',
        **GROUP_INSTANCES
    ),
    'region': settings.StringSetting(
        display_name='Region',
        description='AWS region',
        default='us-east-1',
        values=[region for region in Session().get_available_regions('ec2')],
        **GROUP_INSTANCES
    ),
    'zone': settings.StringSetting(
        display_name='Zone',
        description='AWS zone',
        **GROUP_INSTANCES
    ),
    'placementgroup': settings.StringSetting(
        display_name='Placement group',
        description='The name of the placement group instances will be'
                    ' created in',
        **GROUP_INSTANCES
    ),

    #
    # Authentication
    #
    'awsaccesskey': settings.StringSetting(
        display_name='Access key',
        description='AWS Access key ID',
        secret=True,
        requires=['awssecretkey'],
        mutually_exclusive=['credential_vault_path'],
        **GROUP_AUTHENTICATION
    ),
    'awssecretkey': settings.StringSetting(
        display_name='Secret key',
        description='AWS secret access key',
        secret=True,
        requires=['awsaccesskey'],
        mutually_exclusive=['credential_vault_path'],
        **GROUP_AUTHENTICATION
    ),
    'credential_vault_path': settings.StringSetting(
        display_name='Credential Vault Path',
        description='Path to AWS credentials stored in Vault.',
        mutually_exclusive=['awssecretkey', 'awsaccesskey'],
        **GROUP_AUTHENTICATION
    ),
    'iam_instance_profile_name': settings.StringSetting(
        display_name='IAM instance profile',
        description='IAM Instance Profile (IIP) name to associate with '
                    'new node instance(s)',
        **GROUP_AUTHENTICATION
    ),
    'keypair': settings.StringSetting(
        display_name='SSH keypair',
        description='Name of AWS SSH keypair to install on new node '
                    'instances. The keypair must be previously created in'
                    ' AWS',
        required=True,
        **GROUP_AUTHENTICATION
    ),

    #
    # DNS
    #
    'override_dns_domain': settings.BooleanSetting(
        display_name='Override DNS domain',
        description='Enable overriding of instances\' DNS domain',
        default='False',
        **GROUP_DNS
    ),
    'dns_domain': settings.StringSetting(
        display_name='DNS domain',
        description='DNS search order to be configured on instances',
        requires=['override_dns_domain'],
        **GROUP_DNS
    ),
    'dns_options': settings.StringSetting(
        display_name='DNS options',
        description='Specifies the "options" field in /etc/resolv.conf '
                    'on new node instances',
        requires=['override_dns_domain'],
        **GROUP_DNS
    ),
    'dns_nameservers': settings.StringSetting(
        display_name='DNS nameservers',
        description='Specifies the "nameservers" field in '
                    '/etc/resolv.conf on compute node instances and is '
                    'a space-separated list of IP addresses',
        requires=['override_dns_domain'],
        list=True,
        list_separator=' ',
        **GROUP_DNS
    ),
    'use_domain_from_dhcp_option_set': settings.BooleanSetting(
        display_name='Use DNS domain configured in DHCP option set',
        default='False',
        **GROUP_DNS
    ),
    'use_instance_hostname': settings.BooleanSetting(
        display_name='Use instance hostname',
        description='When true, the AWS-assigned host name will be '
                    'used as the host name for new instances',
        default='True',
        **GROUP_DNS
    ),
    'use_reverse_dns_hostname': settings.BooleanSetting(
        display_name='Use reverse DNS lookup of instance private IP to'
                     ' determine host name',
        default='False',
        requires=['use_instance_hostname'],
        **GROUP_DNS
    ),

    #
    # Networking
    #
    'securitygroup': settings.StringSetting(
        display_name='Security group',
        description='AWS security group. This security group must allow '
                    'unrestricted access between the Tortuga installer '
                    'and compute instances.',
        list=True,
        **GROUP_NETWORKING
    ),
    'subnet_id': settings.StringSetting(
        display_name='Subnet',
        description='AWS subnet ID for new node instances',
        **GROUP_NETWORKING
    ),
    'associate_public_ip_address': settings.BooleanSetting(
        display_name='Automatically assign public IP address when set to'
                     ' \'true\'',
        default='True',
        **GROUP_NETWORKING
    ),

    #
    # Spot
    #
    'enable_spot': settings.BooleanSetting(
        display_name='Enable spot instance requests.',
        **GROUP_SPOT
    ),
    'spot_price': settings.FloatSetting(
        display_name='Price when bidding on spot instances',
        requires=['enable_spot'],
        **GROUP_SPOT
    ),

    #
    # API
    #
    'endpoint': settings.StringSetting(
        display_name='API endpoint',
        description='AWS (or compatible) API endpoint',
        **GROUP_API
    ),
    'proxy_host': settings.StringSetting(
        display_name='Proxy host used for AWS communication',
        **GROUP_API
    ),
    'proxy_port': settings.IntegerSetting(
        display_name='Proxy port used for AWS communication',
        **GROUP_API
    ),
    'proxy_user': settings.StringSetting(
        display_name='Proxy username used for AWS communication',
        **GROUP_API
    ),
    'proxy_pass': settings.StringSetting(
        display_name='Proxy password used for AWS communication',
        secret=True,
        **GROUP_API
    ),

    #
    # Settings for Navops Launch 2.0
    #
    'cost_sync_enabled': settings.BooleanSetting(
        display_name='Cost Synchronization Enabled',
        description='Enable AWS cost synchronization',
        requires=['cost_bucket_name', 'cost_bucket_prefix'],
        **GROUP_COST
    ),
    'cost_bucket_name': settings.StringSetting(
        display_name='Bucket Name',
        requires=['cost_sync_enabled'],
        description='The name of the AWS bucket where cost '
                    'reports are saved',
        **GROUP_COST
    ),
    'cost_bucket_prefix': settings.StringSetting(
        display_name='Bucket Prefix',
        requires=['cost_sync_enabled'],
        description='File path prefix for cost reports',
        **GROUP_COST
    ),

    #
    # Unspecified
    #
    'installer_ip': settings.StringSetting(
        display_name='Override automatically detected installer IP'
                     ' address. This may be required for multi-homed'
                     ' installers.'
    ),
    'launch_timeout': settings.IntegerSetting(
        display_name='Launch timeout',
        description='Wait time (in seconds) for launch request to'
                    ' complete',
        default='300'
    ),
    'createtimeout': settings.IntegerSetting(
        display_name='Create timeout',
        description='Wait time (in seconds) for instance launch(es) to'
                    ' complete',
        default='900',
        advanced=True
    ),
    'sleeptime': settings.IntegerSetting(
        display_name='Sleep time',
        description='Time (in seconds) between attempts to update EC2 '
                    'instance status to avoid thrashing',
        default='5',
        advanced=True
    ),
    'aki': settings.StringSetting(advanced=True),
    'ari': settings.StringSetting(advanced=True),
    'healthcheck_period': settings.IntegerSetting(
        display_name='Helthcheck period',
        description='Wait time (in seconds) between healthchecks',
        default='300',
        advanced=True
    ),
}

