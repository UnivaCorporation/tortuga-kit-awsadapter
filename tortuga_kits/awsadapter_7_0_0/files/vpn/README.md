## Starting up VPN

- Network attached to `eth0`: 192.168.0.0/24
- Network attached to `eth1`: 10.2.0.0/24
- AWS key pair: `mykeypair`
- VPC tagged with name `myvpc`
- Security group for `myvpc`: sg-XXXXXXXX

```shell
VPC_NAME=myvpc ./init-vpn.sh \
    --local-networks 192.168.0.0/24,10.2.0.0/24 \
    --key-name mykeypair --securitygroup sg-XXXXXXXX
```

## Tearing down VPN

```shell
./teardown-vpn.sh
```
