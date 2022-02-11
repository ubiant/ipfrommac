# IpFromMac
----
IpFromMac is a golang library to retrieve IPv4 address from a MAC address.
The library is based on the arpscan example from the [gopacket library](https://github.com/google/gopacket).

## Installation
Directly as a go package:
```bash
import "github.com/ubiant/ipfrommac"
```
With the getIpFromMac command:
```bash
go get github.com/ubiant/ipfrommac
go build github.com/ubiant/ipfrommac/cmd/getIpFromMac
```

## Usage
```bash
./getIpFromMac interface_name mac_address
```
