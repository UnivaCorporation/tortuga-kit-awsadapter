#!/bin/bash

[[ -n $TORTUGA_ROOT ]] || {
    echo "Error: TORTUGA_ROOT is undefined; Tortuga environment must be sourced before running this script" >&2
    exit 1
}

rpm -q openvpn &>/dev/null || {
    echo "Warning: openvpn package is not installed" >&2
}

# Ensure 'aws' CLI is in PATH
type -P aws &>/dev/null || {
    echo "Error: aws CLI not found in PATH. Unable to proceed." >&2
    exit 1
}

vpc_name="${VPC_NAME:-tortuga-vpc}"
vpn_instance_name="tortuga-vpn"
vpn_network_cidr="10.8.0.0/24"
local_network_cidr="10.2.0.0/24"

# Amazon Linux image ID
default_ami="ami-c58c1dd3"
default_instance_type="t2.nano"

verbose=0
force=0
unattended=0

if ! $(type -P ipcalc &> /dev/null); then
    echo "Error: this script requires 'ipcalc' (found on most Linuxes)"
    exit 1
fi

function cidr2mask()
{
  local maskpat="255 255 255 255"
  local maskdgt="254 252 248 240 224 192 128"
  set -- ${maskpat:0:$(( ($1 / 8) * 4 ))}${maskdgt:$(( (7 - ($1 % 8)) * 4 )):3}
  echo ${1-0}.${2-0}.${3-0}.${4-0}
}

function mask2cdr()
{
  # Assumes there's no "255." after a non-255 byte in the mask
  local x=${1##*255.}
  set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
  x=${1%%$3*}
  echo $(( $2 + (${#x}/4) ))
}

readonly vpn_network_addr=$(echo $vpn_network_cidr | cut -f1 -d/)
readonly vpn_network_netmask=$(cidr2mask $(echo $vpn_network_cidr | cut -f2 -d/))

TEMP=$(getopt -o v,f,y --long verbose,force,key-name:,local-networks:,region:,ami: -- "$@")
[[ $? -eq 0 ]] || {
    echo "Terminating..." >&2
    exit 1
}

eval set -- "$TEMP"

while true; do
    case "$1" in
        -v|--verbose)
            verbose=1
            shift
            ;;
        -f|--force)
            force=1
            shift
            ;;
        -y)
            unattended=1
            shift
            ;;
        --key-name)
            keyname=$2
            shift 2
            ;;
        --local-networks)
            local_network_cidr=$2
            shift 2
            ;;
        --region)
            region=$2
            shift 2
            ;;
        --ami)
            ami=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Internal error!" >&2
            exit 1
            ;;
    esac
done

[[ -n $region ]] && [[ $region != us-east-1 ]] && [[ -z $ami ]] && {
    echo "Error: --ami=ami-XXXXXXXX must be specified when using region other than us-east-1" >&2
    exit 1
}

common_args=

[[ -n $region ]] && common_args+=" --region $region"

# Check if instance already exists
[[ $force -eq 0 ]] && [[ -z $1 ]] && {
    aws ec2 describe-instances $common_args --filter "Name=instance-state-name,Values=running --filter" "Name=tag:Name,Values=$vpn_instance_name" --output text --query "Reservations[0]" | grep -q ^INSTANCES

    if [[ $? -eq 0 ]]; then
        echo "Instance ${vpn_instance_name} already exists"
        exit 0
    fi
}

echo -n "Determining VPC ID for VPC [${vpc_name}]... "

vpc_id=$(aws ec2 describe-vpcs $common_args --filter "Name=tag:Name,Values=${vpc_name}" --output text | grep ^VPCS | cut -f7)

if [[ -z $vpc_id ]]; then
    echo "not found."
    exit 1
fi

echo "$vpc_id"

readonly remote_network_cidr=$(aws ec2 describe-vpcs $common_args --output=text --vpc-ids $vpc_id | grep ^VPCS | cut -f2)

if [[ $? -ne 0 ]] || [[ -z $remote_network_cidr ]]; then
    echo "Error: unable to query VPC [${vpc_id}]" >&2
    exit 1
fi

readonly remote_network_addr=$(echo $remote_network_cidr | cut -f1 -d/)
readonly remote_network_netmask=$(ipcalc --netmask ${remote_network_cidr} | cut -f2 -d=)

echo
[[ -n $region ]] && echo "                       AWS region: ${region}"
[[ -z $region ]] && echo "                       AWS region: <default>"
echo "         Amazon EC2 instance name: ${vpc_name}"
[[ -z $keyname ]] && echo "                         Key name: <default>"
[[ -n $keyname ]] && echo "                         Key name: ${keyname}"
[[ -n $ami ]] &&    echo "                 Amazon EC2 image: ${ami}"
echo "      Amazon VPC (remote) network: ${remote_network_cidr}"
echo "                      VPN network: ${vpn_network_cidr}"
echo "                 Local network(s): ${local_network_cidr}"
echo

# Split comma-separated list of local networks
readonly local_cidrs_array=(${local_network_cidr//,/ })

if [[ $unattended -ne 1 ]]; then
    echo "Warning: this script will start a Amazon EC2 instance"
    echo
    echo -n "Do you wish to proceed [N/y]? "
    read PROMPT

    if [[ -z $PROMPT ]] || [[ $(echo $PROMPT | tr [YN] [yn] | cut -c1) != "y" ]]; then
        exit 1
    fi
fi

if [[ -z $1 ]]; then
    echo -n "Getting security group... "

    security_group_id=$(aws ec2 describe-security-groups $common_args --filter "Name=vpc-id,Values=${vpc_id}" --output text | grep ^SECURITYGROUPS | cut -f3)

    if [[ -z $security_group_id ]]; then
        echo "not found."

        echo "Error: unable to determine security group for VPC ${vpc_id}" >&2

        exit 1
    fi

    echo $security_group_id

    echo -n "Getting subnet ID... "
    subnet_id=$(aws ec2 describe-subnets --filter "Name=vpc-id,Values=${vpc_id}" --query "Subnets[0].SubnetId" | tr -d \")

    if [[ ${subnet_id} == null ]] || [[ -z $subnet_id ]]; then
        echo "failed."
        echo "Error: unable to determine subnet for VPC ${vpc_id}" >&2
        exit 1
    fi

    echo "$subnet_id"

    # Create keys/certificates
    certdir="$TORTUGA_ROOT/etc/certs"
    [[ -d $certdir/openvpn-aws-server ]] || {
        echo "Creating OpenVPN server credentials..."

        # Create server certificate
        $TORTUGA_ROOT/bin/mkcert.sh --server \
            --destdir $certdir/openvpn-aws-server --host-name server server
        [[ $? -eq 0 ]] || {
            echo "Error creating OpenVPN server key and certificate" >&2
            exit 1
        }
    }

    [[ -d $certdir/openvpn-aws-client ]] || {
        echo "Creating OpenVPN client credentials..."

        # Create client key/certificate
        $TORTUGA_ROOT/bin/mkcert.sh --destdir $certdir/openvpn-aws-client \
            --host-name client client
        [[ $? -eq 0 ]] || {
            echo "Error creating OpenVPN client key and certificate" >&2
            exit 1
        }
    }

    [[ -f /etc/openvpn/dh2048.pem ]] || {
        echo "Creating Diffie Hellman parameter for OpenVPN"
        openssl dhparam -out /etc/openvpn/dh2048.pem 2048
        [[ $? -eq 0 ]] || {
            echo "Error creating Diffie Hellman parameter" >&2
            exit 1
        }
    }

    echo -n "Creating OpenVPN server configuration... "

    # Use the first element in the array to populate @LOCAL_NETWORK@/@LOCAL_NETMASK@
    readonly local_network_addr=$(echo ${local_cidrs_array[0]} | cut -f1 -d/)
    readonly local_network_netmask=$(cidr2mask $(echo ${local_cidrs_array[0]} | cut -f2 -d/))

    sed -e "s/@VPN_NETWORK@/$vpn_network_addr/" \
        -e "s/@VPN_NETMASK@/$vpn_network_netmask/" \
        -e "s/@REMOTE_NETWORK@/$remote_network_addr/" \
        -e "s/@REMOTE_NETMASK@/$remote_network_netmask/" \
        -e "s/@LOCAL_NETWORK@/$local_network_addr/" \
        -e "s/@LOCAL_NETMASK@/$local_network_netmask/" \
        < server.conf.ec2.tmpl >server.ec2.conf

    if [[ $? -ne 0 ]]; then
        echo "failed."

        exit 1
    fi

    [[ ${#local_cidrs_array[@]} -gt 1 ]] && {
        tmp_network=$(echo ${local_cidrs_array[1]} | cut -f1 -d/)
        tmp_netmask=$(cidr2mask $(echo ${local_cidrs_array[1]} | cut -f2 -d/))

        sed -i -e "s/@LOCAL_NETWORK2@/$tmp_network/" \
            -e "s/@LOCAL_NETMASK2@/$tmp_netmask/" server.ec2.conf
    }

    echo "done."

    echo -n "Creating startup script... "

    sed -e "s/@server_key@/$(base64 -w0 $certdir/openvpn-aws-server/server.key)/" \
        -e "s/@server_crt@/$(base64 -w0 $certdir/openvpn-aws-server/server.crt)/" \
        -e "s/@ca_crt@/$(base64 -w0 $TORTUGA_ROOT/etc/CA/ca.pem)/g" \
        -e "s/@server_conf@/$(base64 -w0 server.ec2.conf)/g" \
        -e "s/@dh2048_pem@/$(base64 -w0 /etc/openvpn/dh2048.pem)/" \
        -e "s/@LOCAL_NETWORK@/$local_network_addr/" \
        -e "s/@LOCAL_NETMASK@/$local_network_netmask/" \
        < startup-script.ec2.sh.tmpl >startup-script.ec2.sh

    if [[ $? -ne 0 ]]; then
      echo "failed."
      exit 1
    fi

    [[ ${#local_cidrs_array[@]} -gt 1 ]] && {
        tmp_local_second_network=$(echo ${local_cidrs_array[1]} | cut -f1 -d/)
        tmp_local_second_netmask=$(cidr2mask $(echo ${local_cidrs_array[1]} | cut -f2 -d/))

        sed -i -e "s/@LOCAL_NETWORK2@/$tmp_local_second_network/" \
            -e "s/@LOCAL_NETMASK2@/$tmp_local_second_netmask/" startup-script.ec2.sh
    }

    echo "done."

    echo -n "Starting EC2 instance... "

    [[ -n $keyname ]] && args+=" --key-name $keyname"

    launch_cmd="aws ec2 run-instances $common_args --output text --user-data file://startup-script.ec2.sh --image-id $default_ami $args --security-group-ids $security_group_id --instance-type $default_instance_type --subnet $subnet_id --associate-public-ip-address"

    [[ -n $ami ]] && launch_cmd+=" --image-id $ami"

    result=$($launch_cmd)

    [[ $? -eq 0 ]] || {
        echo "failed."
        echo "Error launching instance in VPC ${vpc_id}" >&2
        exit 1
    }

    readonly oldifs="$IFS"
    IFS=

    instance_id=$(echo $result | grep "^INSTANCES" | cut -f8)
    [[ -z $instance_id ]] && {
        echo "Error: unable to determine instance ID. Unable to proceed!" >&2
        exit 1
    }
else
    instance_id=$1

    echo -n "Using instance ID argument... "
fi

IFS="$oldifs"

echo "$instance_id"

route_table_id=$(aws ec2 describe-route-tables $common_args --filter "Name=vpc-id,Values=${vpc_id}" --output text | grep ^ROUTETABLES | cut -f 2)

# Wait for instance to reach running state
echo -n "Waiting for instance to reach running state... "
for ((i=0; i<40; i++)); do
    result=$(aws ec2 describe-instances $common_args --filter "Name=instance-state-name,Values=running" --instance-id $instance_id --output text)

    if [[ -n $result ]]; then break; fi

    sleep 3
done

if [[ $i -eq 24 ]]; then
    echo "timed out"
    echo "Error: timed out waiting for instance ${instance_id} to reach 'running' state" >&2
    exit 1
fi

echo "done."

aws ec2 modify-instance-attribute $common_args --instance-id $instance_id --no-source-dest-check

if [[ $? -ne 0 ]]; then
    echo "Error modifying instance attribute for instance $instance_id" >&2
    exit 1
fi

# Add tag to instance
aws ec2 create-tags $common_args --resources $instance_id --tag "Key=Name,Value=${vpn_instance_name}"


# Delete existing routes

echo -n "Deleting existing routes (if necessary)... "

for local_cidr in ${local_cidrs_array[@]}; do
    aws ec2 delete-route $common_args --route-table-id $route_table_id \
        --destination-cidr-block $local_cidr &>/dev/null
done

echo "done."

# Set up routes for VPN

echo "Setting up routing... "

for local_cidr in ${local_cidrs_array[@]}; do
    echo -n "   Creating route for ${local_cidr}... "

    aws ec2 create-route $common_args --route-table-id $route_table_id \
        --destination-cidr-block $local_cidr --instance-id $instance_id &>/dev/null

    [[ $? -eq 0 ]] || {
        echo "failed."
        exit 1
    }

    echo "done."
done

aws ec2 delete-route $common_args --route-table-id $route_table_id \
    --destination-cidr-block $vpn_network_cidr &>/dev/null

aws ec2 create-route $common_args --route-table-id $route_table_id \
    --destination-cidr-block $vpn_network_cidr --instance-id $instance_id &>/dev/null

[[ $? -eq 0 ]] || {
    echo "failed."
    exit 1
}

echo "done."

readonly remote_ip=$(aws ec2 describe-instances $common_args --output text --query "Reservations[0].Instances[0].PublicIpAddress" --instance-id $instance_id)

echo "Determining VPN instance IP... $remote_ip"

# Update OpenVPN client configuration
readonly client_conf=client-aws.conf
sed -e "s/@remote_ip@/$remote_ip/" < ${client_conf}.tmpl >$client_conf

echo -n "Copying $client_conf to /etc/openvpn/$(basename $client_conf)... "
cp -f $client_conf /etc/openvpn/$(basename $client_conf)
echo "done."
