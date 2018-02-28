### Troubleshooting ###

1. DNS resolution not working

    Symptoms: Kubernetes cluster will appear to be running normally (ie. `kubectl get nodes` will show worker nodes having properly joined the cluster), however pods will fail to run successfully.

    Solution: Ensure `--dns-servers` is passed to `init-vpc.sh`. This sets up the DHCP option set with the Tortuga DNS server as the DNS server for all EC2 instances.

    If necessary, the DHCP option set can be changed manually after the initial VPC is set up. Create a DHCP option set with the value of "Domain name servers" set to that of the provisioning interface IP on Tortuga.
