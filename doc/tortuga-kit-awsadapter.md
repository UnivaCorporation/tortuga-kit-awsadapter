# AWS Resource Adapter Kit

February 2019 -- Version 1.1

## Overview

[Amazon Elastic Compute Cloud][amazon ec2] support is enabled in Tortuga
through the installation and activation of the AWS resource adapter kit.

The AWS resource adapter kit provides a resource adapter that can be used to
perform the following functions on an AWS-compatible cloud:

- Add and delete node instances
- Run a Tortuga installer node from within an AWS-compatible cloud
- Run a Tortuga installer node from outside an AWS-compatible cloud (also known
  as _hybrid_ mode)

The AWS adapter maps each AWS instance to a Tortuga compute node. It also adds
support for _cloud bursting_ by providing the capability to automate
cloud-based node addition/removal.

## Installing the AWS resource adapter kit

The AWS Adapter Kit installs as a standard kit using `install-kit`:

```shell
install-kit kit-awsadapter-7.0.3-0.tar.bz2
```

### Enable management component

Before proceeding with configuration of the AWS resource adapter, it is first necessary to enable the `management` component on the Tortuga installer:

```shell
enable-component -p awsadapter-7.0.3-0 management-7.0.3
puppet agent -t
```

After installing the AWS Adapter Kit and enabling the management component, the
following changes are made within Tortuga:

### Create resource adapter configuration profile

```shell
adapter-mgmt create --resource-adapter AWS --profile Default \
    --setting awsaccesskey=<AWS access key> \
    --setting awssecretkey=<AWS secret key> \
    --setting keypair=<keypair name> \
    --setting ami=<ami-XXXXXXXX> \
    --setting instancetype=<AWS instance type> \
    --setting user_data_script_template=<user data script template> \
    --setting securitygroup=<AWS security group> \
    --setting region=<AWS region>
```

Use one of the following values for `user_data_script_template`:

- `bootstrap.tmpl` for RHEL/CentOS 6 &amp; 7 and recent Amazon Linux
    versions
- `bootstrap.python3.tmpl` for Fedora 23/24/25
- `bootstrap.debian.tmpl` for recent Debian/Ubuntu versions
- `bootstrap.suse.tmpl` for SUSE Linux/openSUSE versions

**Note:** If you set the VPC, region, subnet, or security group to be
different than that of the Tortuga Installer, it WILL NOT WORK by default,
as additional networking setup will need to be done in AWS. The details of
these configuration changes are highly case-specific, and thus are not
covered in this document.

## Creating AWS Hardware Profile

To create an AWS hardware profile using the default hardware profile
template, an additional step is necessary:

```shell
create-hardware-profile --name AWS
update-hardware-profile --name AWS --location remote \
    --resource-adapter AWS
```

Using `set-profile-mapping`, map this hardware profile to an existing software profile or create a new software profile for EC2-based compute nodes.

## Updating AWS resource adapter configuration

Use the command-line tool `adapter-mgmt update` to update an existing resource
adapter configuration.

For example, to change the instance type for `Default` resource adapter
configuration profile:

```shell
adapter-mgmt update -r AWS -p Default -s instancetype=XXXXXXXX
```

See the [AWS resource adapter configuration reference](#aws-resource-adapter-configuration-reference)
for valid settings for the AWS resource adapter.

## AWS resource adapter configuration reference

This section lists the valid settings for the AWS resource adapter.

- `ami`

    AMI ID to be used when launching compute node instances.

    Paravirtual (PV) and hardware virtual machine (PVM) AMIs are supported,
    however PVM AMIs are recommended for better performance.

    **Note:** 64-bit AMIs must be used in either instance.

- `associate_public_ip_address`

    Valid values: _true_ or _false_

    Ensure instances have an associated public IP address. This setting can
    be set globally for the VPC subnet. Unless explicitly set, the default
    setting will be used.

- `awsaccesskey` and `awssecretkey`

    These are the API keys for the cloud user account under which instances
    should be managed. A pre-existing AWS account is required prior to
    using the Tortuga AWS resource adapter.

- `block_device_map`

    Specify block device map for compute node instances.

    See "[Advanced Topics: AWS instance block device mapping](#aws-instance-block-device-mapping)" section below
    for full detail and examples.

- `cloud_init` and `user_data_script_template`

    These control the scripts that set up and configure Puppet and fully
    integrate the instance into a Tortuga cluster.

    The `cloud_init` parameter may be set to `false` if Tortuga should create
    instances (nodes), but do no management of the software on those nodes.

    The default [`cloud-init`][cloud_init] script
    `$TORTUGA_ROOT/config/bootstrap.tmpl` can be modified by the end-user to
    perform custom bootstrapping of AWS nodes added by Tortuga.

    **Note:** `cloud_init` does not need to be set if
    `user_data_script_template` is set.

- `endpoint`

    This is intended primarily for other AWS-compatible clouds. It should be
    set to the hostname or IP address of the system that accepts API requests
    for managing instances.

    **Note:** This setting is **not** required for [Amazon EC2][] and is
    intended mainly for cloud providers with an AWS-compatible API.

- `iam_instance_profile_name`

    IAM Instance Profile (IIP) name to associate with the instance(s).

    This is the name of the IAM Role to associate with Tortuga-launched
    instances. If the Tortuga installer is hosted on EC2 and IAM is in effect,
    the IAM role policy must include the "iam:PassRole" permission.

- `instancetype`

    Compute node instance type

    Specify the type of compute node instances created in the AWS cloud.  The
    instance must support 64-bit images, and further must support the image
    specified by **ami**. Since no prelaunch validation of the **instancetype**
    is performed, errors related to an invalid instance type are reported at
    instance launch time.

    Consult corresponding AWS provider documentation for valid values.

- `keypair`

    Name of a keypair previously defined in the AWS-compatible cloud, allowing
    SSH access.

    **Note:** The specified keypair must previously exist.

- `override_dns_domain`, `dns_options`, `dns_nameservers`

    Allow the compute node bootstrap process to manage `/etc/resolv.conf`.
    This enables support for a custom DNS suffix outside of the configuration
    provided by [Amazon VPC][].

    `dns_options` specifies the "options" field in `/etc/resolv/conf` on
    compute node instances.

    `dns_nameservers` specifies the "nameservers" field in `/etc/resolv.conf`
    on compute node instances and is a space-separated list of IP addresses.

    See the section _DNS and AWS_ for additional information.

- `region`, `zone`, and `placementgroup`

    Tortuga will automtically use region "us-east-1" on AWS (or first available
    region on non-AWS plaforms).

    For example, to use zone "us-east-1e", set the following:

    ```shell
    region = us-east-1
    zone = us-east-1e
    ```

    Specify `zone` and/or `placementgroup` to further customize exact location
    where compute node instances will be launched.

- `securitygroup`

    Must be set to a security group allowing unrestricted access between the
    Tortuga installer and compute instances. If the security group is not
    specified, a security group named 'default' will be used. The end-user is
    responsible for properly configuring access through the security group.

- `subnet_id`

    Specify the [Amazon VPC][] subnet ID for instances to use.

    **Note:** only the `subnet_id` (and not the VPC ID) need to be specified in
    the AWS resource adpater configuration.

- `tags`

    User-defined AWS tags are automatically added to all instances. Tags in AWS
    can be used to classify or group similar instances. For example, to clearly
    identify all instances within in the same cluster.

    They should be specified as key-value pairs in the format `key:value`.
    Multiple tags should be separated by spaces.

    For keys and/or values containing spaces, enclose the spaces in
    double-quotes.

    Simple example:

    ```shell
    adapter-mgmt update --resource-adapter AWS --profile Default \
        --setting "tags=owner=admin"
    ```

  Tag name/values containing spaces:

    ```shell
    adapter-mgmt update --resource-adapter AWS --profile Default \
        --setting tags="key=value \"this is the tag name=this is the tag value\""
    ```

  Multiple tags:

    ```shell
    adapter-mgmt update --resource-adapter AWS --profile Default \
        --setting tags="Name=\"execd host\" ostype=centos"
    ```

- `use_instance_hostname`

    When set to "true", the AWS-assigned host name will be used. This requires
    the hardware profile name format to be set to "\*" (see
    `update-hardware-profile` documentation for information on setting hardware
    profile name format). When disabled (value `false`), the hardware profile
    name format is used to generate host names.

    When Tortuga is hosted on AWS, `use_instance_hostname` is automatically
    enabled and can be disabled, which requires additional DNS configuration.

    See section [DNS and AWS](#dns-and-aws).

- `vcpus`

    Set number of virtual CPUs for resource adapter configuration profile.

    When the AWS resource adapter is used in conjunction with Univa Grid
    Engine, this value will be used to automatically configure Grid Engine the
    exechost slots.

    Mapping of AWS instance type to vcpus can be done automatically using the
    lookup file.

    See [AWS instance type to VCPU mapping](#instance-type-to-vcpu-mapping)

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

Red Hat Enterprise Linux and CentOS both offer access to AMIs through the [AWS Marketplace][].
In either case, there is no additional charge for the software through the [AWS Marketplace][],
however Red Hat AMIs require access to the Red Hat Network (subscriptiona
available through Red Hat).

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

## DNS and AWS

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

1. Set custom DNS zone

    ```shell
    set-private-dns-zone cloud.univa.com
    ```

    Use `set-private-dns-zone` without any argument to display the current
    private DNS zone.

2. Update hardware profile(s) name format

    ```shell
    update-hardware-profile --name execd --name-format aws-#NN
    ```

    Using this example, generated host names will appear as follows:

    ```shell
    aws-01.cloud.univa.com
    aws-02.cloud.univa.com
    aws-03.cloud.univa.com
    ...
    ```

3. Enable DNS server on Tortuga

    ```shell
    enable-component -p dns
    puppet agent -t
    ```

    Restart Grid Engine qmaster to allow DNS settings to take place:

    ```shell
    service sgemaster.tortuga stop
    service sgemaster.tortuga start
    ```

4. Apply settings to AWS resource adapter

    ```shell
    adapter-mgmt update -r AWS -p Default \
        -s override_dns_domain=true \
        -s use_instance_hostname=false
    ```

### How do I specify custom DNS options, search spec and/or nameservers for compute node instances?

Enable managed `/etc/resolv.conf` and specify `dns_options`, `dns_search`,
and/or `dns_nameservers`. For example:

```shell
adapter-mgmt update -r AWS -p Default \
    -s override_dns_domain=true \
    -s dns_options="timeout:2 attempts:5" \
    -s dns_nameservers="8.8.8.8 8.8.4.4"
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

- `add-nodes`
- `delete-node`
- `reboot-node`
- `shutdown-node`
- `startup-node`

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

Using an [Amazon VPC][], allows an administrator more control over their
compute instances. This includes allowing setting of instance IP addresses,
network address space, routing, DNS, etc.

Ensure the setting `subnet_id` is applied when using an [Amazon VPC][]:

```shell
adapter-mgmt update --resource-adapter AWS --profile Default \
    --setting subnet_id=<subnet-XXXXXXXX>
```

Please refer to [Amazon VPC][] documentation for further information.

## EC2 Spot Instance support

### Spot Instance Overview

Tortuga supports EC2 Spot Instances through a standalone companion service
named `awsspotd`. This service **must** be started manually in order to
activate support for EC2 spot instances.

### Prerequisites

- Tortuga must either be hosted on AWS or using an externally managed VPN

    This is necessary because of the need for AWS-assigned instance host names.

    Custom DNS host names for spot instances are **not** currently supported!

- AWS resource adapter must be previously configured

    Ensure `add-nodes` works against the "Default" AWS resource adapter
    configuration profile prior to attempting to use spot instance support.

### Setting up EC2 Spot Instance support

EC2 Spot Instance support is not enabled by default in Tortuga. The EC2 Spot
Instance support daemon (`awsspotd`) must be manually enabled and started
before it is capable of requesting and monitoring spot instance requests.

1. Configure AWS credentials

    If not using [AWS Identity and Access Management][aws iam], it is necessary
    to configure a credentials file.

    Create a `/root/.aws/credentials` file with these contents:

    ```shell
    [Credentials]
    aws_access_key_id = YOURACCESSKEY
    aws_secret_access_key = YOURSECRETKEY
    ```

1. Enable and start `awsspotd` service

    RHEL/CentOS 7

    ```shell
    systemctl enable awsspotd
    systemctl start awsspotd
    ```

    RHEL/CentOS 6

    ```shell
    chkconfig awsspotd on
    service awsspotd start
    ```

#### Configuration

##### Region

Change the AWS region used by changing the value of the `--region NAME`
argument set by `AWSSPOTD_OPTIONS` in `/etc/sysconfig/awsspotd`. If no
`--region` argument is specified, the default region is set to `us-east-1`.

The value of `--region` **must** match the region set in the resource
adapter configuration.

For example, to change the AWS region to `us-west-2`, add (or uncomment)
the following line to `/etc/sysconfig/awsspotd` as follows:

```shell
AWSSPOTD_OPTIONS="--region us-west-2"
```

**Note:** it is necessary to restart `awsspotd` after making any changes
to `/etc/sysconfig/awsspotd`.

##### Polling interval

The default polling interval for `awsspotd` is 60 seconds.

Every 60 seconds, `awsspotd` will query the state of spot instance requests
made using `request-spot-instances`. It is not recommended to set this
interval too short as each spot instance request query makes multiple
requests to the AWS EC2 backend.

### Usage

Use `request-spot-instances` to make requests for EC2 spot instances. In the
following example, the spot instance bid price is the current spot price for
the configured instance type:

```shell
[root@tortuga ~]# request-spot-instances \
    --software-profile Navops_Demo-Compute \
    --hardware-profile AWS \
    --count 3
Do you wish to request 3 t2.large spot instance(s) @ $0.027800/hour [N/y]? y
[root@tortuga ~]#
```

Skip the confirmation prompt with the argument `--assume-yes` (`--yes`, for
short).

The price can be specified using `--price XXX`, where `XXX` is the price in
dollars per hour:

```shell
[root@tortuga ~]# request-spot-instances \
    --software-profile Navops_Demo-Compute \
    --hardware-profile AWS \
    --count 3 \
    --price 0.0277
Requesting 3 t2.large spot instance(s) @ $0.0277/hour
[root@tortuga ~]#
```

#### Display existing spot instance requests

Use `list-spot-instance-requests`:

```shell
[root@tortuga ~]# list-spot-instance-requests
sir-9fb8675g open pending-fulfillment
sir-hv684p4g active fulfilled
sir-nnti4r1k active fulfilled
[root@tortuga ~]#
```

The first column is the actual EC2 spot instance request id, which can be
cross-referenced on the AWS Console or through the `aws ec2` CLI.

The second column shows the state of the spot instance request.

The third column shows the status code.

Spot instances with associated nodes will display as follows:

```shell
[root@tortuga ~]# list-spot-instance-requests
sir-9fb8675g (ip-10-241-0-184.ec2.internal) active fulfilled
sir-hv684p4g (ip-10-241-0-249.ec2.internal) active fulfilled
sir-nnti4r1k (ip-10-241-0-34.ec2.internal) active fulfilled
[root@tortuga ~]#
```

`list-spot-instance-nodes` will show names of nodes that were added to Tortuga
as a result of fulfilled spot instance requests:

```shell
[root@tortuga ~]# list-spot-instance-nodes
ip-10-241-0-6.ec2.internal
ip-10-241-0-244.ec2.internal
ip-10-241-0-227.ec2.internal
[root@tortuga ~]#
```

#### Cancelling spot instance requests

The CLI `cancel-spot-instance-requests` is used to cancel spot instance
requests made using `request-spot-instances`. It optionally takes the
`--terminate` argument to terminate any instances that were started as a
result of spot instance fulfillment:

```shell
[root@tortuga ~]# cancel-spot-instance-requests sir-9fb8675g
Cancelling 1 spot instance requests
[root@tortuga ~]#
```

Without the `--terminate` argument, the instance from this spot instance
request fulfillment will remain running. This instance can be removed
using `delete-node` in Tortuga.

To cancel all spot instance requests and terminate instances, use the
following:

```shell
[root@tortuga ~]# cancel-spot-instance-requests --all --terminate
Cancelling 2 spot instance requests in region [Default]
Deleting 2 node(s)
[root@tortuga ~]#
```

#### Query current spot instance pricing

Use the CLI `get-current-spot-instance-price` to query the current spot
instance bid price.

This uses the currently configured default resource adapter configuration
profile:

```shell
[root@tortuga ~]# get-current-spot-instance-price
us-east-1a t2.large 0.027800 Linux/UNIX (Amazon VPC)
[root@tortuga ~]#
```

Use `--resource-adapter-configuration` to specify an alternate resource
adapter configuration profile. For example, this is useful for alternate
configurations where the instance type and/or availability zone is different.

To display current spot instance prices for all availability zones, use
`--availability-zone all`:

```shell
[root@tortuga ~]# get-current-spot-instance-price --availability-zone all
us-east-1a t2.large 0.027800 Linux/UNIX (Amazon VPC)
us-east-1b t2.large 0.027800 Linux/UNIX (Amazon VPC)
us-east-1c t2.large 0.027800 Linux/UNIX (Amazon VPC)
us-east-1d t2.large 0.027800 Linux/UNIX (Amazon VPC)
us-east-1e t2.large 0.027800 Linux/UNIX (Amazon VPC)
us-east-1f t2.large 0.027800 Linux/UNIX (Amazon VPC)
[root@tortuga ~]#
```

**Hint:** set up a separate hardware profile and resource adapter
configuration profile for each availability zone to allow full coverage of
spot instances for your workload.

### Troubleshooting

- Use AWS management console or [AWS CLI][aws cli] `aws ec2` to manage spot
  instance requests.

- Run daemon in debug/foreground mode

    Stop the `awsspotd` daemon using `systemctl` (or `service`, on
    RHEL/CentOS 6) and use `--debug` command-line argument to run
    `awsspotd` in debug mode.

- Use `systemctl status awsspotd` (or `service awsspotd status` on
  RHEL/CentOS 6) to ensure spot instance support daemon is running. Use
  `journalctl -u awsspotd --follow` to see any output from `awsspotd` on
  RHEL/CentOS 7.

### Known Issues

- Custom DNS domain names cannot be used with spot instances

- Spot instance requests must be made through `request-spot-instances`
  instead of `add-nodes` with additional spot related arguments.

- Logging/debugging/troubleshooting

    EC2 Spot Instance operations may not be logged with sufficient
    verbosity to assist with debugging.

- No support for multiple AWS accounts

    Only the account credentials defined by the IAM profile (or AWS
    credentials file) are currently used by the EC2 Spot Instance support.

- Spot Fleets not currently supported

    EC2 Spot Fleets are not currently supported in this release.

## Advanced Topics

### Instance type to VCPU mapping

The AWS platform does not provide the ability to automatically query instance
type metadata, so it is necessary to provide a mapping mechanism.

This mapping is contained within the comma-separted value formatted file
`$TORTUGA_ROOT/config/aws-instances.csv` to allow Tortuga to
automatically set UGE exechost slots.

This file can be modified by the end-user. The file is the AWS instance type
followed by a comma and the number of VCPUs for that instance type. Some
commonly used instance type to VCPUs mappings are included in the default
installation.

### AWS instance block device mapping

AWS allows setting various parameters on the block devices (virtual hard
drives) associated with an instance. This includes setting the root device
size, the disk type (ie. standard or SSD), # of IOPS, and encryption.

These settings are exposed through the AWS resource adapter using the option
`block_device_map` in the AWS resource adapter configuration.

Refer to the [Block Device Mapping][bdm] (under `ec2-run-instances`) documentation for block device mapping syntax and options.

Note: not all block device mappings are valid for all instance types. Not all
instance types have the option of adding ephemeral storage. Some instance types
permit multiple ephemeral disks.

See instance type details at [Amazon EC2 Instance Types][instance types].

As with all configuration options, adding to the `Default` resource adapter
configuraiton profile will change the setting for all AWS instances managed by
Tortuga. These options can be set on hardware profile specific sections as
well.

#### Set root device size to 60GB

If the root device for the image is `/dev/sda`, the following command will set
the root device size to 60GB.

```shell
adapter-mgmt update --resource-adapter AWS --profile Default \
    --setting block_device_map=/dev/sda=:60
```

Note the leading ':' is necessary to delineate the first argument
(`snapshot_id`) from the second (`size`).

The root device name can be obtained by displaying details of the AMI. For
official RHEL/CentOS 6 AMIs, it is usually `/dev/sda` or `/dev/sda1` and for
official RHEL/CentOS 7 AMIs, it is `/dev/xvda`.

Hint: use `aws ec2 describe-images --image-id` and pay attention to the `RootDeviceName` attribute. This is the value that must be specified as the root device name.

#### Use SSD root device

- General purpose SSD

    Enable the General Purpose (gp2) SSD:

    ```shell
    adapter-mgmt update --resource-adapter aws --profile Default \
        setting block_device_map=/dev/sda1=:::gp2
    ```

- High performance SSD

    Enable high performance SSD with `io1` modifier followed by the requested
    operations per second:

    ```shell
    adapter-mgmt update --resource-adapter aws --profile Default \
        setting block_device_map=/dev/sda1=:::io1:1000
    ```

The same `block_device_map` settings may be applied to EBS volumes using the
same syntax.

**Note**: if is not possible to change the device type of an
ephemeral volume. Refer to EC2 documentation regarding the disk type associated
with instance types that support ephemeral disks.

#### Use 60GB SSD-backed root device

Assuming the root device is `/dev/sda1`:

```shell
adapter-mgmt update --resource-adapter AWS --profile Default \
    setting block_device_map=/dev/sda1=:60::gp2
```

#### Add an ephemeral disk

```shell
adapter-mgmt update --resource-adapter AWS --profile Default \
    --setting block_device_map=/dev/xvdb=ephemeral0
```

For Amazon EC2 instance types that have the option of multiple ephemeral
disks, separate the block device mappings using commas:

```shell
adapter-mgmt update --resource-adapter AWS --profile Default \
    --setting block_device_map=/dev/xvdb=ephemeral0,/dev/xvdc=ephemeral1
```

#### Set root device size and add an ephemeral disk

Separate device mappings with a comma.

```shell
adapter-mgmt update --resource-adapter AWS --profile Default \
    --setting block_device_map=/dev/sda=:60,/dev/sdb=ephemeral0
```

#### Add EBS (data) volume

Create 100GB EBS volume attached on `/dev/xvdc` and marked for deletion on
termination.

```shell
adapter-mgmt update --resource-adapter AWS --profile Default \
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
VPN or [AWS Direct Connect][directconnect] is in use.

Enable `use_instance_hostname` as follows:

```shell
adapter-mgmt update --resource-adapter AWS --profile Default \
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
desirable to disallow instances from accessing the Internet. In the context
of Tortuga, for example, this implies that all operating system packages
must be served by the Tortuga installer (or other AWS infrastructure node).

The default [`cloud-init`][cloud_init] script (template found in
`$TORTUGA_ROOT/config/bootstrap.tmpl`) generated for compute instances by
Tortuga assumes compute instances will have unrestricted Internet access.
This script template **must** be modified by the end-user to properly
retrieve package dependencies from the Tortuga installer or other
infrastructure node.

### Multiple AWS-compatible Clouds

By default, the AWS adapter supports a single AWS-compatible cloud.
However, it is possible to configure it to support multiple clouds
simultaneously, such as both [Amazon EC2][] or multiple different profiles
for [Amazon EC2][].

Each AWS configuration is associated with a single hardware profile. To
create an additional AWS-compatible hardware profile, copy the pre-defined
AWS profile as follows:

```shell
copy-hardware-profile --src AWS --dst <NAME>
```

If desired, update the new profile using `update-hardware-profile` to
specify a different description, different modules, node name format, etc.

All AWS-enabled hardware profiles may use the same resource adapter
configuration profile, or it may be desirable to create new resource
adapter configuration profiles for different instance types, availability
zones, etc.

In this example, the AWS resource adapter configuration profiles might look
as follows:

```shell
adapter-mgmt create --resource-adapter AWS --profile Default \
    --setting awsaccesskey=XXXXXXXXXXXXXXXX \
    --setting awssecretkey=YYYYYYYYYYYYYYYY \
    --setting ami=ami-XXXXXXXX
```

Add nodes to EC2:

```shell
add-nodes --count 3 \
    --software-profile <swprofile> \
    --hardware-profile <hwprofile>
```

Remember, if the resource adapter configuration profile is not specified,
the `Default` is used.

## Identity &amp; Access Mangagement (IAM) Policy Requirements

If using IAM when the Tortuga installer is hosted on Amazon EC2, minimally,
the following IAM role policy **must** contain the following actions:

- `ec2:RebootInstances`
- `ec2:DescribeImages`
- `ec2:DescribeVpcAttribute`
- `ec2:DescribeVpcs`
- `ec2:DescribeDhcpOptions`
- `ec2:DescribeSubnets`
- `ec2:RunInstances`
- `ec2:StartInstances`
- `ec2:StopInstances`
- `ec2:TerminateInstances`
- `ec2:DescribeInstances`
- `ec2:DescribeInstanceStatus`
- `ec2:CreateTags`
- `ec2:DescribeTags`

The following additional permissions must be enabled for spot instance support:

- `ec2:DescribeSpotInstanceRequests`
- `ec2:DescribeSpotPriceHistory`
- `ec2:CancelSpotInstanceRequests`
- `ec2:RequestSpotInstances`

### IAM Role Usage

The IAM role must be specified as a parameter when launching the EC2
instance that is acting as the Tortuga installer. This applies to the
official Tortuga AMI as well as any custom-built Tortuga installer
instances.

The above list of IAM Policy actions does not include permitting passing of
the IAM role. This means EC2 instances launched by Tortuga will not be able
to "inherit" the IAM policy.

Refer to [AWS Identity and Access Management (IAM)][aws iam] documentation
for further details.

## Troubleshooting

Troubleshooting AWS issues can be tedious. Check `/var/log/tortugawsd` and
output of `get-node-requests` for any immediately obvious errors. In the
case of AWS IAM related issues, permissions errors are logged.

Next check network connectivity between the Tortuga installer and AWS
instances. Using simple `ping` is usually enough, although AWS security
groups can also restrict access to specific network ports.

The following are some commonly observed issues when working with Tortuga
and AWS.

1. EC2 instances unable to communicate with Tortuga installer/VPN gateway

   **Hybrid installation only**

    - ensure network routing between on-presmises Tortuga installer
    - check security group settings allow network egress from AWS through VPN/Direct Connect.

1. EC2 instances are launched but never provisioned; unable to ping instances
   created by Tortuga

    - Ensure security group of Tortuga installer matches the security group of
      the compute nodes.
    - Ensure security group allows access to instances within same security
      group.
    - Ensure Tortuga installer is on same [Amazon VPC][] subnet as compute
      nodes

1. EC2 instances launch but do not appear to be running and/or are inaccessible

    Advanced EC2 instance types (ie. r4 series) require Linux driver support
    for the Amazon [Elastic Network Adapter (ena)][ena].
    This support is **not** built into the official CentOS AMIs, for example.

    **Note:** some Amazon Linux and some Debian/Ubuntu AMIs do not support
    `ena`.

1. Ephemeral devices configured via `block_device_map` are not configured

    Ensure the requested instance type supports ephemeral disks. Some instance
    types (ie. m4 series and newer) are EBS only and do not support ephemeral
    disks.

[aws marketplace]: https://aws.amazon.com/marketplace  "AWS Marketplace"
[cloud_init]:      http://cloudinit.readthedocs.org    "cloud-init"
[amazon ec2]:      https://aws.amazon.com/ec2/         "Amazon EC2"
[amazon vpc]:      https://aws.amazon.com/vpc/         "Amazon VPC"
[ena]:             https://aws.amazon.com/blogs/aws/elastic-network-adapter-high-performance-network-interface-for-amazon-ec2/
[aws iam]:         https://aws.amazon.com/iam/         "AWS Identity and Access Management (IAM)"
[instance types]:  https://aws.amazon.com/ec2/instance-types/ "Amazon EC2 Instance Types"
[bdm]:             http://docs.aws.amazon.com/AWSEC2/latest/CommandLineReference/ApiReference-cmd-RunInstances.html "Block Device Mapping"
[directconnect]:  https://aws.amazon.com/directconnect/ "AWS Direct Connect"
[aws cli]:        https://aws.amazon.com/cli/           "AWS Command Line Interface"
