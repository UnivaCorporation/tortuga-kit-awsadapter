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

vpn_instance_name="${VPN_INSTANCE_NAME:-tortuga-vpn}"

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

echo "Tearing down VPN instance [${vpn_instance_name}]"

echo -n "Determining instance ID... "

instance_id=$(aws ec2 describe-instances --output text \
    --filter Name=tag:Name,Values=tortuga-vpn \
    --query "Reservations[0].Instances[0].InstanceId")

if [[ $? -ne 0 ]] || [[ $instance_id == None ]]; then
    echo "not found"

    echo "Instance [${vpn_instance_name}] does not exist"

    exit 0
fi

echo "$instance_id"

echo -n "Removing instance tag... "

aws ec2 delete-tags $common_args --output=text --resources $instance_id \
    --tags Key=Name,Value="$vpn_instance_name" &>/dev/null

echo "done."

echo -n "Terminating instance ${instance_id}... "

aws ec2 terminate-instances $common_args --output=text --instance-ids $instance_id &>/dev/null

echo "done."
