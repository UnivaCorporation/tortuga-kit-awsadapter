#!/bin/bash

remote_network="10.241.0.0/24"
vpc_name="${VPC_NAME:-tortuga-vpc}"
unattended=0
force=0

TEMP=$(getopt -o v,f,y --long verbose,force,remote-network:,region: -- "$@")
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
        --remote-network)
            remote_network=$2
            shift 2
            ;;
        --region)
            region=$2
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

# Attempt to validate region
[[ -n $region ]] && {
    echo -n "Validating specified AWS region... "
    aws ec2 describe-regions --output=text | cut -f3 | grep -qx $region
    retval=$?

    echo "done."

    [[ $retval -ne 0 ]] && {
        echo "Error: invalid region $region specfied" >&2

        exit
    }
}

common_args=

[[ -n $region ]] && common_args+=" --region $region"

# Check for existing VPC
[[ $force -eq 0 ]] && {
    result=$(aws ec2 describe-vpcs $common_args --output=text | grep ^TAGS | awk "\$2 ~ /Name/ && \$3 ~ /^${vpc_name}\$/")
    [[ -n $result ]] && {
        echo "Amazon VPC [${vpc_name}] already exists. Use --force to override."
        exit 1
    }
}

echo
echo "   Amazon VPC name: $vpc_name"
[[ -n $region ]] && echo " Amazon VPC region: $region"
[[ -z $region ]] && echo " Amazon VPC region: <default>"
echo "    Remote network: $remote_network"
echo

[[ $unattended -ne 1 ]] && {
    echo "Warning: this script will create an Amazon VPC"
    echo
    echo -n "Do you wish to proceed [N/y]? "
    read PROMPT

    if [[ -z $PROMPT ]] || [[ $(echo $PROMPT | tr [YN] [yn] | cut -c1) != "y" ]]; then
        exit 1
    fi
}

echo -n "Creating VPC [$vpc_name] with remote network [${remote_network}]... "

vpc_id=$(aws ec2 create-vpc $common_args --output=text --cidr-block $remote_network | cut -f6)

[[ $? -eq 0 ]] || {
    echo "Error creating VPC with remote network ${remote_network}" >&2

    exit 1
}

# Assign name to newly created VPC
aws ec2 create-tags $common_args --resources $vpc_id --tag "Key=Name,Value=${vpc_name}"

echo "$vpc_id"

# Create DHCP options set using optional --dns-servers argument
echo -n "Creating DHCP option set... "

# As per http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_DHCP_Options.html
if [[ -z $region ]] || [[ $region == us-east-1 ]]; then
    dhcp_domain="ec2.internal"
else
    dhcp_domain="${region}.compute.internal"
fi

# Sorry :(
#
# copy-and-paste this at a shell prompt and pipe to 'python -mjson.tool'
# to validate.

cli_input_json="{\"DhcpConfigurations\": [{\"Key\": \"domain-name-servers\", \"Values\": [\"AmazonProvidedDNS\"]}, {\"Key\": \"domain-name\", \"Values\": [\"$dhcp_domain\"]}]}"

dhcp_options_id=$(aws ec2 create-dhcp-options $common_args --output=text --cli-input-json "$cli_input_json" | grep ^DHCPOPTIONS | cut -f2)

[[ -n $dhcp_options_id ]] || {
    echo "failed."
    echo "Error creating DHCP option set. Unable to proceed!" >&2
    exit 1
}

aws ec2 create-tags $common_args --resources $dhcp_options_id --tag "Key=Name,Value=${vpc_name}"

echo "${dhcp_options_id}"

# Associate DHCP options set with VPC
echo -n "Associating DHCP option set with VPC... "
aws ec2 associate-dhcp-options $common_args --dhcp-options-id $dhcp_options_id --vpc-id $vpc_id

[[ $? -eq 0 ]] || {
    echo "failed."
    echo "Error associating DHCP option set with VPC. Unable to proceed!" >&2
    exit 1
}

echo "done."

# Create subnet
echo -n "Creating subnet... "
subnet_id=$(aws ec2 create-subnet $common_args --output=text --vpc-id $vpc_id --cidr-block $remote_network | cut -f6)

[[ $? -eq 0 ]] || {
    echo "failed."
    echo "Error adding subnet to VPC $vpc_id" >&2
    exit 1
}

echo "${subnet_id}"

aws ec2 create-tags $common_args --resources $subnet_id --tag "Key=Name,Value=${vpc_name}"

# Ensure public IPs are assigned on launch
echo -n "Setting subnet to auto-assign public IPs on launch... "
aws ec2 modify-subnet-attribute $common_args --subnet-id $subnet_id --map-public-ip-on-launch
[[ $? -eq 0 ]] || {
    echo "failed."
    exit 1
}

echo "done."

# Create Internet gateway
echo -n "Creating Internet gateway... "
internet_gateway_id=$(aws ec2 create-internet-gateway $common_args --output text | cut -f2)

if [[ $? -ne 0 ]] || [[ -z $internet_gateway_id ]]; then
    echo "failed."
    echo "Error creating Internet gateway" >&2

    exit 1
fi

echo "$internet_gateway_id"

# Attach internet gateway to VPC
echo -n "Attaching Internet gateway to VPC... "
aws ec2 attach-internet-gateway $common_args --internet-gateway-id $internet_gateway_id --vpc-id $vpc_id
if [[ $? -ne 0 ]]; then
    echo "failed."

    exit 1
fi

echo "done."

# Get route table
route_table_id=$(aws ec2 describe-route-tables $common_args --filter "Name=vpc-id,Values=${vpc_id}" --output text | grep ^ROUTETABLES | cut -f 2)

# Associate route table with subnet
aws ec2 associate-route-table $common_args --output=text \
    --subnet-id $subnet_id \
    --route-table-id $route_table_id &>/dev/null

[[ $? -eq 0 ]] || {
    echo "Error: unable to associate route table [$route_table_id] to subnet [$subnet_id]" >&2
    exit 1
}

# Add default route to internet gateway
echo -n "Creating default route for egress... "
aws ec2 create-route $common_args --output=text \
    --route-table-id $route_table_id \
    --destination-cidr-block 0.0.0.0/0 \
    --gateway-id $internet_gateway_id &>/dev/null

[[ $? -eq 0 ]] || {
  echo "failed."
  echo "Error: unable to create default route for egress. Unable to proceed!" >&2
  exit 1
}

echo "done."

echo -n "Creating default security group... "

# Get security group
security_group_id=$(aws ec2 describe-security-groups $common_args --filter "Name=vpc-id,Values=${vpc_id}" --output text | grep ^SECURITYGROUPS | cut -f3)

if [[ $? -ne 0 ]] || [[ -z $security_group_id ]]; then
    echo "failed."
    echo "Error getting default security group. Unable to proceed!" >&2
    exit 1
fi

# Update security group
aws ec2 create-tags $common_args --resources $security_group_id --tag "Key=Name,Value=${vpc_name}"

echo "${security_group_id}"

echo "Done."

echo
echo "Update security group [${security_group_id}] as follows:"
echo

cmd="aws ec2 authorize-security-group-ingress"

[[ -n $common_args ]] && cmd+=" $common_args"

echo "$cmd --group-id $security_group_id \\"
echo "    --protocol tcp --port 22 --cidr <external CIDR>"
echo
echo "$cmd --group-id $security_group_id \\"
echo "    --protocol udp --port 1194 --cidr <external CIDR>"
echo
