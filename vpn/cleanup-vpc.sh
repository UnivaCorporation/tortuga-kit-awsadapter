#!/bin/bash

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

vpc_name="${VPC_NAME:-tortuga-vpc}"

TEMP=$(getopt -o v,f,y --long verbose,force,region: -- "$@")
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

common_args=

[[ -n $region ]] && common_args+=" --region $region"

if [[ -z $1 ]]; then
    # Get VPC
    readonly vpc_id=$(aws ec2 describe-vpcs $common_args --filter "Name=tag:Name,Values=${vpc_name}" --output text | grep ^VPCS | cut -f7)

    if [[ -z $vpc_id ]]; then
        echo "VPC [${vpc_name}] not found" >&2
        exit 1
    fi
else
    readonly vpc_id=$1
fi

echo "Tearing down VPC [$vpc_id]"

echo -n "Deleting subnets... "

# Delete subnets associated with VPC
subnet_id=$(aws ec2 describe-subnets $common_args --filter "Name=vpc-id,Values=${vpc_id}" --output text | cut -f8)

if [[ -n $subnet_id ]]; then
    aws ec2 delete-subnet $common_args --subnet-id $subnet_id
fi

echo "done."

# Get route table
route_table_id=$(aws ec2 describe-route-tables $common_args --filter "Name=vpc-id,Values=${vpc_id}" --output text | grep ^ROUTETABLES | cut -f2)

# Get internet gateway
internet_gateway_id=$(aws ec2 describe-internet-gateways $common_args --filter "Name=attachment.vpc-id,Values=${vpc_id}" --output text | grep ^INTERNETGATEWAYS | cut -f2)

if [[ -n $internet_gateway_id ]]; then
    # Detach internet gateway from vpc
    echo -n "Detaching Internet gateway... "
    aws ec2 detach-internet-gateway $common_args --internet-gateway-id $internet_gateway_id --vpc-id $vpc_id
    echo "done."

    # Delete internet gateway
    echo -n "Deleting Internet gateway... "
    aws ec2 delete-internet-gateway $common_args --internet-gateway-id $internet_gateway_id
    echo "done."
fi

echo -n "Deleting VPC... "
aws ec2 delete-vpc $common_args --vpc-id $vpc_id
echo "done."

# Get DHCP options
dhcp_options_id=$(aws ec2 describe-dhcp-options $common_args --filter "Name=tag:Name,Values=${vpc_name}" --output text | grep ^DHCPOPTIONS | cut -f2)

if [[ -n $dhcp_options_id ]]; then
    # Delete DHCP options
    echo -n "Deleting DHCP option set... "
    aws ec2 delete-dhcp-options $common_args --dhcp-options-id $dhcp_options_id
    echo "done."
fi

# security_group_id=$(aws ec2 describe-security-groups --filter "Name=vpc-id,Values=${vpc_id}" --output text | grep ^SECURITYGROUPS | cut -f3)

