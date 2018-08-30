# AWS resource adapter kit

## Overview

[Amazon Elastic Compute Cloud][amazon ec2] support is enabled in Tortuga
through the installation and activation of the AWS resource adapter kit.

The AWS resource adapter kit provides a resource adapter that can be used to
perform the following functions on an AWS-compatible cloud:

- Add and delete node instances
- Run a Tortuga installer node from within an AWS-compatible cloud
- Run a Tortuga installer node from outside an AWS-compatible cloud (also known as _hybrid_ mode)

The AWS adapter maps each AWS instance to a Tortuga compute node. It also adds
support for _cloud bursting_. When used in conjunction with the _Tortuga Simple
Policy Engine_, it allows for user-defined policy to automatically add (and
remove) AWS-based compute nodes based on user-defined metrics (such as cluster
load).

## Installing the AWS resource adapter kit

The AWS Adapter Kit installs as a standard kit using `install-kit`:

```shell
install-kit kit-awsadapter-6.3.1-0.tar.bz2
```

After installing the AWS Adapter Kit and enabling the management component, the following changes are made within Tortuga:

1.  The `AWS` hardware profile is created. This profile uses the AWS resource adapter for node management. Any nodes provisioned in a mapped software profile (see documentation for `set-profile-mapping`) with be provisioned on the configured AWS cloud provider.

    Note: the AWS hardware profile is only created if a provisioning network is configured at the time of the AWS Adapter Kit being installed. It can be manually created as described below.

1.  Create resource adapter configuration profile

        adapter-mgmt create --resource-adapter aws --profile default \
            --setting awsAccessKey=<AWS access key> \
            --setting awsSecretKey=<AWS secret key> \
            --setting keypair=<keypair name> \
            --setting ami=<ami-XXXXXXXX> \
            --setting instancetype=<AWS instance type> \
            --setting user_data_script_template=<user data script template> \
            --setting securitygroup=<AWS security group> \
            --setting region=<AWS region>

    Use one of the following values for `user_data_script_template`:

    - `bootstrap.tmpl` for RHEL/CentOS 6 &amp; 7 and recent Amazon Linux versions
    - `bootstrap.python3.tmpl` for Fedora 23/24/25
    - `bootstrap.debian.tmpl` for recent Debian/Ubuntu versions
    - `bootstrap.suse.tmpl` for SUSE Linux/openSUSE versions

1.  Before AWS instances can be managed in an AWS-based cloud, the AWS
    **management** component _must_ be enabled on the installer. The Tortuga
    **dns** component _must_ also be enabled to map Tortuga-assigned host names to
    AWS instances.

         enable-component -p awsadapter-6.3.1-0 management-6.3.1 --no-sync
         enable-component -p base-6.3.1-0 dns-6.3.1

## Creating AWS Hardware Profile

To create an AWS hardware profile using the default hardware profile template,
an additional step is necessary:

```shell
create-hardware-profile --name AWS
update-hardware-profile --name AWS --location remote --cost 10 \
    --resource-adapter aws
```

For advanced installations, it may be desirable to set the "cost" of the
cloud-based instances to be higher and/or lower if the installation has
multiple AWS hardware profiles associated with different instance types.

## Updating AWS resource adapter configuration

Use the command-line tool `adapter-mgmt update` to update an existing resource
adapter configuration.

For example, to change the instance type for "default" resource adapter
configuration profile:

```shell
adapter-mgmt update -r aws -p default -s instancetype=XXXXXXXX
```

See the [AWS resource adapter configuration reference](#aws_cfg_reference)
for valid settings for the AWS resource adapter.

## AWS resource adapter configuration reference {#aws_cfg_reference}

This section lists the valid settings for the AWS resource adapter.

- `ami`

  AMI ID to be used when launching compute node instances.

  Paravirtual (PV) and hardware virtual machine (PVM) AMIs are supported,
  however PVM AMIs are recommended for better performance. 64-bit AMIs
  must be used in either instance.

- `associate_public_ip_address`

    Valid values: _true_ or _false_

    Ensure instances have an associated public IP address. This setting can be set globally for the VPC subnet. Unless explicitly set, the default setting will be used.

- `awsAccessKey` and `awsSecretKey`

  These are the API keys for the cloud user account under which instances
  should be managed. A pre-existing AWS account is required prior to using
  the Tortuga AWS resource adapter.

- `block_device_map`

  Specify block device map for compute node instances.

  See "Advanced Topics: AWS instance block device mapping" section below
  for full detail and examples.

- `cloud_init` and `user_data_script_template`

  These control the scripts that set up and configure Puppet and fully
  integrate the instance into a Tortuga cluster.

  The `cloud_init` parameter may be set to `false` if Tortuga should create
  instances (nodes), but do no management of the software on those nodes.

  The default [`cloud-init`][cloud_init] script
  `$TORTUGA_ROOT/config/bootstrap.tmpl` can be modified by the end-user
  to perform custom bootstrapping of AWS nodes added by Tortuga.

  **Note:** `cloud_init` does not need to be set if
  `user_data_script_template` is set.

- `endpoint`

  This is intended primarily for other AWS-compatible clouds. It should
  be set to the hostname or IP address of the system that accepts API
  requests for managing instances.

  **Note:** This setting is **not** required for [Amazon EC2][] and is intended
  mainly for cloud providers with an AWS-compatible API.

- `iam_instance_profile_name`

  IAM Instance Profile (IIP) name to associate with the instance(s).

  This is the name of the IAM Role to associate with Tortuga-launched
  instances. If the Tortuga installer is hosted on EC2 and IAM is in
  effect, the IAM role policy must include the "iam:PassRole" permission.

- `instancetype`

  Compute node instance type

  Specify the type of compute node instances created in the AWS cloud.
  The instance must support 64-bit images, and further must support the
  image specified by **ami**. Since no prelaunch validation of the
  **instancetype** is performed, errors related to an invalid instance
  type are reported at instance launch time.

  Consult corresponding AWS provider documentation for valid values.

- `keypair`

  Name of a keypair previously defined in the AWS-compatible cloud,
  allowing SSH access.

  **Note:** The specified keypair must previously exist.

- `override_dns_domain`, `dns_search`, `dns_options`, `dns_nameservers`

  Allow the compute node bootstrap process to manage `/etc/resolv.conf`.
  This enables support for a custom DNS suffix outside of the
  configuration provided by [Amazon VPC][].

  `dns_search` specifies the DNS search order to be configured on
  compute node instances.

  `dns_options` specifies the "options" field in `/etc/resolv/conf` on
  compute node instances.

  `dns_nameservers` specifies the "nameservers" field in
  `/etc/resolv.conf` on compute node instances and is a space-separated
  list of IP addresses.

  See the section _DNS and AWS_ for additional information.

- `region`, `zone`, and `placementgroup`

  Tortuga will automtically use region "us-east-1" on AWS (or first
  available region on non-AWS plaforms).

  For example, to use zone "us-east-1e", set the following:

        region = us-east-1
        zone = us-east-1e

  Specify "zone" and/or "placementgroup" to further customize exact
  location where compute node instances will be launched.

- `securitygroup`

  Must be set to a security group allowing unrestricted access between
  the Tortuga installer and compute instances. If the security group is
  not specified, a security group named 'default' will be used. The
  end-user is responsible for properly configuring access through the
  security group.

- `subnet_id`

  Specify the [Amazon VPC][] subnet ID for instances to use.

  **Note:** only the `subnet_id` (and not the VPC ID) need to be
  specified in the AWS resource adpater configuration.

- `tags`

  User-defined AWS tags are automatically added to all instances. Tags
  in AWS can be used to classify or group similar instances. For example,
  to clearly identify all instances within in the same cluster.

  They should be specified as key-value pairs in the format `key:value`.
  Multiple tags should be separated by spaces.

  For keys and/or values containing spaces, enclose the spaces in
  double-quotes.

  Simple example:

        adapter-mgmt update --resource-adapter aws --profile default \
            --setting "tags=owner=admin"

  Tag name/values containing spaces:

        adapter-mgmt update --resource-adapter aws --profile default \
            --setting tags="key=value \"this is the tag name=this is the tag value\""

  Multiple tags:

        adapter-mgmt update --resource-adapter aws --profile default \
            --setting tags="Name=\"execd host\" ostype=centos"

- `use_instance_hostname`

  When set to "true", the AWS-assigned host name will be used. This
  requires the hardware profile name format to be set to "\*" (see
  `update-hardware-profile` documentation for information on setting
  hardware profile name format). When disabled (value `false`), the
  hardware profile name format is used to generate host names.

  When Tortuga is hosted on AWS, `use_instance_hostname` is
  automatically enabled and can be disabled, which requires additional
  DNS configuration.

  See section [DNS and AWS](#dns_and_aws).

- `vcpus`

  Set number of virtual CPUs for resource adapter configuration profile.

  When the AWS resource adapter is used in conjunction with Univa Grid
  Engine, this value will be used to automatically configure Grid Engine
  the exechost slots.

  Mapping of AWS instance type to vcpus can be done automatically using
  the lookup file. See [AWS instance type to VCPU mapping](#instance_mapping)

Refer to the Advanced Topics section below for further discussion on
supporting multiple clouds. This capability can also be used to support
different instance types for different hardware profiles.

## AMI Requirements

All AMIs for Amazon EC2 used for deploying Tortuga compute nodes must contain
a Tortuga-compatible operating system and have [cloud-init][cloud_init]
enabled for bootstrapping.

For most Tortuga installations, a custom AMI containing a compatible operating
system (with [cloud-init][cloud_init] enabled) and installation-specific
applications and/or datasets would be optimal. When creating custom AMIs, be
sure to be aware of operating system state (ie. host name) contained within
image snapshots used to create the AMI.

### Amazon EC2

Red Hat Enterprise Linux and CentOS both offer access to AMIs through the [AWS
Marketplace][]. In either case, there is no additional charge for the software
through the [AWS Marketplace][], however Red Hat AMIs require access to the Red
Hat Network (subscriptiona available through Red Hat).

Third-party AMIs (created by vendors other than Red Hat and CentOS) may also be
used, as well as custom AMIs as long as they meet [`cloud-init`][cloud_init]
requirements.

## Security Group Requirements

The recommended configuration for AWS-based clouds is a security group which
grants _full_ access to all other instances running in the same security group.
This prevents communications from being blocked internally.

If this configuration is not possible, see the _Firewall Configuration_ section
in Tortuga Installation and Installation Guide for a list of ports which must
allow ingress in the security group.

## DNS and AWS {#dns_and_aws}

In an on-premise Tortuga installer (hybrid installation) scenario, Tortuga
will automatically generate host names for AWS instances. These generated host
names are resolved using the built-in DNS server. For a Tortuga installer
running on AWS, it is possible to configure Tortuga to allow generating host
names and using a custom DNS suffix. This functionality is provided in addition
to the [Amazon VPC][] functionality that allows for custom name servers and DNS
domain.

### How do I use a custom DNS suffix for compute node instances?

Through the use of the built-in support for a Tortuga-managed DNS server, it
is possible to have a custom DNS domain assigned to your compute nodes.

The following steps are required to enable a custom DNS suffix:

1.  Set custom DNS zone

        set-private-dns-zone cloud.univa.com

    Use `set-private-dns-zone` without any argument to display the current
    private DNS zone.

2.  Update hardware profile(s) name format

        update-hardware-profile --name execd --name-format aws-#NN

    Using this example, generated host names will appear as follows:

        aws-01.cloud.univa.com
        aws-02.cloud.univa.com
        aws-03.cloud.univa.com
        ...

3.  Enable DNS server on Tortuga

        enable-component -p dns

    Restart Grid Engine qmaster to allow DNS settings to take place.

        service sgemaster.tortuga stop
        service sgemaster.tortuga start

4.  Apply settings to AWS resource adapter

        adapter-mgmt update -r aws -p default \
            -s override_dns_domain=true \
            -s use_instance_hostname=false

### How do I specify custom DNS options, search spec and/or nameservers for compute node instances?

Enable managed `/etc/resolv.conf` and specify `dns_options`, `dns_search`,
and/or `dns_nameservers`. For example:

```shell
adapter-mgmt update -r aws -p default \
    -s override_dns_domain=true \
    -s dns_options="timeout:2 attempts:5" \
    -s dns_nameservers="8.8.8.8 8.8.4.4" \
    -s dns_search="cloud.mydomain.com mydomain.com"
```

The resulting `/etc/resolv.conf` on the compute node instance would be
similar to as follows:

```shell
options timeout:2 attempts:5
search cloud.mydomain.com mydomain.com
nameserver W.X.Y.Z
nameserver 8.8.8.8
nameserver 8.8.4.4
```

where `W.X.Y.Z` is the IP address of the Tortuga (DNS) server.

In general, it is not usually desirable to set `dns_nameservers` as it
will cause the DNS resolution behaviour to be different from that of
the Tortuga installer. Use customized DNS configuration on the
Tortuga installer and let the built-in DNS server propagate those
settings to the compute nodes.

## AWS resource adapter usage

### Supported Node Operations

The AWS adapter supports the following Tortuga node management commands:

- `activate-node`
- `add-nodes`
- `delete-node`
- `idle-node`
- `reboot-node`
- `transfer-node`
- `shutdown-node`
- `startup-node`

The AWS adapter _does not_ support the following node operation commands as they do not make sense within the context of cloud-based compute nodes:

- `checkpoint-node`
- `migrate-node`

### Networking Considerations

To enable a _true_ hybrid environment with local compute nodes (physical and/or
virtual) and cloud-based compute nodes, the network subnet used for the VPN
needs to be the same as the network where the local compute nodes are
connected.

### Adding Nodes

Nodes are added using the Tortuga `add-nodes` command. Specifying an
AWS-enabled hardware profile (hardware profile with resource adapter set to
`awsadapter`) automatically causes Tortuga to use the AWS resource adapter to
manage the nodes.

For example, the following command-line will add 4 AWS nodes to the software
profile `Compute` and hardware profile `AWS`:

```shell
add-nodes --count 4 --software-profile Compute --hardware-profile AWS
```

## Best Practices

### Amazon Virtual Private Cloud (VPC)

Using an [Amazon VPC][], allows an administrator more control over their compute instances. This includes allowing setting of instance IP addresses, network address space, routing, DNS, etc.

Ensure the setting `subnet_id` is applied when using an [Amazon VPC][]:

```shell
adapter-mgmt update --resource-adapter aws --profile default \
    --setting subnet_id=<subnet-XXXXXXXX>
```

Please refer to [Amazon VPC][] documentation for further information.

## EC2 Spot Instance support

### Overview

Tortuga EC2 Spot Instance support allows Tortuga to manage spot instances requested through the Tortuga provided command-line interfaces.

The basic workflow is as follows:

- Check current spot instance price using the Tortuga CLI `get-current-spot-instance-price`.

  This utility uses the existing AWS resource adapter configuration to determine AWS region, availability zone, and instance type.

  Use the `--resource-adapter-configuration` argument to specify a configuration profile other than "default".

- Request spot instances to be added to specific software/hardware profile

  Request 6 spot instances at the price of $0.0299/hour (2.99 cents per hour). Nodes will be added to the software and hardware profile "execd", respectively:

```shell
    request-spot-instances --price 0.0299 --software-profile execd \
        --hardware-profile execd --count 6
```

  Nodes do not appear in output of `get-node-status` until the spot instance requests have been fulfilled.

- Display existing spot instance requests known to Tortuga using `list-spot-instance-requests`.

- Cancel spot instance requests using `cancel-spot-instance-requests`.

**Note:** spot instance requests made within the AWS Management Console or through AWS command-line interfaces are not known to Tortuga and will not automatically join the Tortuga-managed cluster.

### Prerequisites

- Tortuga must either be hosted on AWS or using an externally managed VPN

  This is necessary because of the need for AWS-assigned instance host names.

- AWS resource adapter must be previously configured

  Ensure `add-nodes` works against the "default" AWS resource adapter
  configuration profile prior to attempting to use spot instance support.

### Setting up EC2 Spot Instance support

EC2 Spot Instance support is not enabled by default in Tortuga. The EC2 Spot
Instance support daemon (`awsspotd`) must be manually enabled and started
before it is capable of requesting and monitoring spot instance requests.

1.  Configure AWS credentials

    If not using [AWS Identity and Access Management](http://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html), it is necessary to configure a credentials file.

    Create a `/root/.boto` file with these contents:

        [Credentials]
        aws_access_key_id = YOURACCESSKEY
        aws_secret_access_key = YOURSECRETKEY

1.  Enable and start `awsspotd` service

    RHEL/CentOS 7

        systemctl enable awsspotd
        systemctl start awsspotd

    RHEL/CentOS 6

        chkconfig awsspotd on
        service awsspotd start

1.  Make spot instance requests

    When spot instance requests are fulfilled, nodes will be automatically
    added to the Tortuga environment.

    If spot instances are marked for termination/terminated, nodes will be
    automatically removed from the cluster.

### Configuration

For example, to change the AWS region to `us-west-2`, add the following line to
`/etc/puppetlabs/code/environments/production/modules/tortuga_kit_awsadapter/files/awsspotd.sysconfig` as follows:

```shell
AWSSPOTD_OPTIONS="--region us-west-2"
```

### Troubleshooting

- Use AWS management console or AWS CLI to query spot instance requests.

- `awsspotd` (Tortuga AWS Spot Instance support service) also logs verbosely
  to `/var/log/tortuga`.

- Use `systemctl status awsspotd` (or `service awsspotd status` on RHEL/CentOS 6) to ensure spot instance support daemon is running. Use `journalctl -u awsspotd` to see any console output from the daemon on RHEL/CentOS 7.

### EC2 Spot Instance limitations/known issues

- Logging/debugging/troubleshooting

  EC2 Spot Instance operations may not be logged with sufficient verbosity to
  assist with debugging.

  Please contact Univa Support <support@univa.com> for assistance in
  troubleshooting failed EC2 Spot Instance operations.

- No support for multiple AWS accounts

  Only the account credentials defined by the IAM profile (or Boto
  credentials file) are currently used by the EC2 Spot Instance support.

- Spot Fleets not currently supported

  EC2 Spot Fleets are not currently supported in this release.

## Advanced Topics

### Instance type to VCPU mapping {#instance_mapping}

The AWS platform does not provide the ability to automatically query instance
type metadata, so it is necessary to provide a mapping mechanism.

This mapping is contained within the comma-separted value formatted file
`$TORTUGA_ROOT/config/aws-instance-sizes.csv` to allow Tortuga to
automatically set UGE exechost slots.

This file can be modified by the end-user. The file is the AWS instance type
followed by a comma and the number of VCPUs for that instance type. Some
commonly used instance type to VCPUs mappings are included in the default
installation.

### AWS instance block device mapping

AWS allows setting various parameters on the block devices (virtual hard drives) associated with an instance. This includes setting the root device size, the disk type (ie. standard or SSD), # of IOPS, and encryption.

These settings are exposed through the AWS resource adapter using the option `block_device_map` in the AWS configuration file. See the example below.

Refer to the [Amazon EC2 command-line reference](http://docs.aws.amazon.com/AWSEC2/latest/CommandLineReference/ApiReference-cmd-RunInstances.html) for block device mapping syntax and options.

Note: not all block device mappings are valid for all instance types. Not all instance types have the option of adding ephemeral storage. Some instance types permit multiple ephemeral disks. See instance type details at [Amazon EC2 Instance Types](https://aws.amazon.com/ec2/instance-types/).

As with all configuration options, adding to the `[default]` section will change the setting for all AWS instances managed by Tortuga. These options can be set on hardware profile specific sections as well. Substitute `[default]` in the following examples as necessary.

#### Example: set root device (`/dev/sda`) size to 60GB

```shell
adapter-mgmt update --resource-adapter aws --profile default \
    --setting block_device_map=/dev/sda=:60
```

Note the leading ':' is necessary to delineate the first argument (`snapshot_id`) from the second (`size`).

The root device name can be obtained by displaying details of the AMI. For official RHEL/CentOS 6 AMIs, it is usually `/dev/sda` or `/dev/sda1` and for official RHEL/CentOS 7 AMIs, it is `/dev/xvda`.

#### Example: use SSD root device

- General purpose SSD:

  Enable the General Purpose (gp2) SSD

        adapter-mgmt update --resource-adapter aws --profile default \
            setting block_device_map=/dev/sda1=:::gp2

- High performance SSD:

  Enable high performance SSD with `io1` modifier followed by the requested
  operations per second:

        adapter-mgmt update --resource-adapter aws --profile default \
            setting block_device_map=/dev/sda1=:::io1:1000

The same `block_device_map` settings may be applied to EBS volumes using the
same syntax. _Note_: if is not possible to change the device type of an
ephemeral volume. Refer to EC2 documentation regarding the disk type associated
with instance types that support ephemeral disks.

#### Example: Use 20GB SSD-backed root device

```shell
adapter-mgmt update --resource-adapter aws --profile default \
    setting block_device_map=/dev/sda1=:60::gp2
```

#### Example: add an ephemeral disk

```shell
adapter-mgmt update --resource-adapter aws --profile default \
    --setting block_device_map=/dev/xvdb=ephemeral0
```

For Amazon EC2 instance types that have the option of multiple ephemeral disks,
separate the block device mappings using commas:

```shell
adapter-mgmt update --resource-adapter aws --profile default \
    --setting block_device_map=/dev/xvdb=ephemeral0,/dev/xvdc=ephemeral1
```

#### Example: set root device size and add an ephemeral disk

Separate device mappings with a comma.

```shell
adapter-mgmt update --resource-adapter aws --profile default \
    --setting block_device_map=/dev/sda=:60,/dev/sdb=ephemeral0
```

#### Example: add EBS (data) volume

Create 100GB EBS volume attached on `/dev/xvdc` and marked for deletion on
termination.

```shell
adapter-mgmt update --resource-adapter aws --profile default \
    --setting block_device_map=/dev/xvdc=:100:true
```

### Using Amazon EC2-assigned instance host names

By default, Tortuga will automatically assign host names to managed Amazon EC2
instances using the name format defined in the EC2-enabled hardware profile.
For example, the default name format for Tortuga-managed EC2 instances is
"`aws-#NN`", meaning Tortuga-assigned instance host names would be
_aws-01.&lt;private DNS suffix&gt;_, _aws-02.&lt;private DNS suffix&gt;_,
_aws-03.&lt;private DNS suffix&gt;_, and so on.

The default naming behaviour can be modified for Tortuga installations where a
VPN or [AWS Direct Connect](https://aws.amazon.com/directconnect/) is in use.

First, enable `use_instance_hostname` in
`$TORTUGA_ROOT/config/adapter-defaults-aws.conf` for all or selected hardware
profiles. To enable this feature for all hardware profiles, and therefore, all
Tortuga-managed instances, the `[default]` section would be configured as
follows:

```shell
adapter-mgmt update --resource-adapter aws --profile default \
    --setting use_instance_hostname=true
```

Once this setting has been enabled, it is necessary to configure the hardware
profiles to allow use of EC2 assigned host names.

```shell
update-hardware-profile --name <hardwareprofilename> --name-format '*'
```

**Note:** Failure to update AWS-enabled hardware profiles will result in errors
when attempting to add AWS nodes.

### Compute instances without Internet access

For security purposes, especially when using [Amazon VPC][], it is often
desirable to disallow instances from accessing the Internet. In the context of
Tortuga, for example, this implies that all operating system packages must be
served by the Tortuga installer (or other AWS infrastructure node).

The default [`cloud-init`][cloud_init] script (template found in
`$TORTUGA_ROOT/config/bootstrap.tmpl`) generated for compute instances by
Tortuga assumes compute instances will have unrestricted Internet access. This
script template **must** be modified by the end-user to properly retrieve
package dependencies from the Tortuga installer or other infrastructure node.

### Multiple AWS-compatible Clouds

By default, the AWS adapter supports a single AWS-compatible cloud. However, it
is possible to configure it to support multiple clouds simultaneously, such as
both [Amazon EC2][] or multiple different profiles for [Amazon EC2][].

Each AWS configuration is associated with a single hardware profile. To create
an additional AWS-compatible hardware profile, copy the pre-defined AWS profile
as follows:

```shell
copy-hardware-profile --src AWS --dst <NAME>
```

If desired, update the new profile using `update-hardware-profile` to specify a
different description, different modules, node name format, etc.

All AWS-enabled hardware profiles may use the same resource adapter
configuration profile, or it may be desirable to create new resource adapter
configuration profiles for different instance types, availability zones, etc.

In this example, the AWS resource adapter configuration profiles might look as
follows:

```shell
adapter-mgmt create --resource-adapter aws --profile default \
    --setting awsAccessKey=XXXXXXXXXXXXXXXX \
    --setting awsSecretKey=YYYYYYYYYYYYYYYY \
    --setting ami=ami-XXXXXXXX
```

Add nodes to EC2:

```shell
add-nodes --count 3 \
    --software-profile <swprofile> \
    --hardware-profile <hwprofile>
```

Remember, if the resource adapter configuration profile is not specified, the
`default` is used.

## Identity &amp; Access Mangagement (IAM) Policy Requirements {#iam_policy}

If using IAM when the Tortuga installer is hosted on Amazon EC2, minimally, the
following IAM role policy **must** contain the following actions:

- ec2:RebootInstances
- ec2:DescribeImages
- ec2:DescribeVpcAttribute
- ec2:DescribeVpcs
- ec2:DescribeDhcpOptions
- ec2:DescribeSubnets
- ec2:RunInstances
- ec2:StartInstances
- ec2:StopInstances
- ec2:TerminateInstances
- ec2:DescribeInstances
- ec2:DescribeInstanceStatus
- ec2:CreateTags
- ec2:DescribeTags

### IAM Role Usage

The IAM role must be specified as a parameter when launching the EC2 instance
that is acting as the Tortuga installer. This applies to the official Tortuga
AMI as well as any custom-built Tortuga installer instances.

The above list of IAM Policy actions does not include permitting passing of the
IAM role. This means EC2 instances launched by Tortuga will not be able to
"inherit" the IAM policy.

Refer to [AWS Identity &amp; Access Management][aws iam] documentation for
further details.

## Troubleshooting

Troubleshooting AWS issues can be tedious. Check `/var/log/tortuga` and output
of `get-node-requests` for any immediately obvious errors. In the case of AWS
IAM related issues, permissions errors are logged.

Next check network connectivity between the Tortuga installer and AWS
instances. Using simple `ping` is usually enough, although AWS security groups
can also restrict access to specific network ports.

The following are some commonly observed issues when working with Tortuga
and AWS.

1. EC2 instances unable to communicate with Tortuga installer/VPN gateway

   **Hybrid installation only**

   Ensure security group of EC2 instances allow inbound port 1194 (UDP)
   network traffic. This is the port used by OpenVPN.

1. EC2 instances are launched but never provisioned; unable to ping instances
   created by Tortuga

   **affects only Tortuga installer hosted in EC2**

   - Ensure security group of Tortuga installer matches the security group
     of the compute nodes.
   - Ensure security group allows access to instances within same security
     group.
   - Ensure Tortuga installer is on same [Amazon VPC][] subnet as compute nodes

1. EC2 instances launch but do not appear to be running and/or are inaccessible

   Advanced EC2 instance types (ie. r4 series) require Linux driver support for
   the Amazon [Elastic Network Adapter (ena)](https://aws.amazon.com/blogs/aws/elastic-network-adapter-high-performance-network-interface-for-amazon-ec2/). This support is **not**
   built into the official CentOS AMIs, for example. Amazon Linux and some
   Debian/Ubuntu AMIs do include support for `ena`.

1. Ephemeral devices configured via `block_device_map` are not configured

   Ensure the requested instance type supports ephemeral disks. Some instance
   types (ie. m4 series and newer) are EBS only and do not support ephemeral disks.

[aws marketplace]: https://aws.amazon.com/marketplace "AWS Marketplace"
[cloud_init]: http://cloudinit.readthedocs.org "cloud-init"
[amazon ec2]: https://aws.amazon.com/ec2/ "Amazon EC2"
[amazon vpc]: https://aws.amazon.com/vpc/ "Amazon VPC"
