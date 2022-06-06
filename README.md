# go-traffic-analyser
## Requirements
### Ubuntu
1. Install [pcap](https://en.wikipedia.org/wiki/Pcap)
```bash
sudo apt install libpcap-dev
```
## Operation
1. Must be run in a privileged shell
```bash
sudo -i
go run main.go
```
## Useful Reading
* [Berkeley Packet Filters](https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters)
* [pcap](https://en.wikipedia.org/wiki/Pcap)
* [Transmission Control Protocol](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)
* [GoPacket pcap](https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcap)
* [GoPacket layers](https://pkg.go.dev/github.com/google/gopacket@v1.1.19/layers)
* [Go net Package](https://pkg.go.dev/net@go1.18.3)