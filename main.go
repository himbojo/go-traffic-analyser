package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Hello returns a greeting for the named person.
func main() {
	if handle, err := pcap.OpenLive("wlo1", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		err = handle.SetBPFFilter("dst host 1.1.1.1")
		if err != nil {
			log.Fatal(err)
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet) // Do something with a packet here.
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	al := packet.ApplicationLayer()
	tltcp := packet.Layer(layers.LayerTypeTCP)
	tludp := packet.Layer(layers.LayerTypeUDP)
	nlipv4 := packet.Layer(layers.LayerTypeIPv4)
	nlipv6 := packet.Layer(layers.LayerTypeIPv6)
	ll := packet.LinkLayer()
	if al != nil && ll != nil {
		printPacket := ""
		if nlipv4 != nil {
			ipv4 := nlipv4.(*layers.IPv4)
			printPacket = fmt.Sprintf("%vSource IPv4: %v|Destination IPv4: %v|Protocol: %v|", printPacket, ipv4.SrcIP, ipv4.DstIP, ipv4.Protocol)
		}
		if nlipv6 != nil {
			ipv6 := nlipv6.(*layers.IPv6)
			printPacket = fmt.Sprintf("%vSource IPv6: %v|Destination IPv6: %v|", printPacket, ipv6.SrcIP, ipv6.DstIP)
		}
		if tltcp != nil {
			tcp := tltcp.(*layers.TCP)
			// can add tcp message types
			printPacket = fmt.Sprintf("%vSource Port: %v|Destination Port: %v|", printPacket, tcp.SrcPort, tcp.DstPort)
		}
		if tludp != nil {
			udp := tludp.(*layers.UDP)
			printPacket = fmt.Sprintf("%vSource Port: %v|Destination Port: %v|", printPacket, udp.SrcPort, udp.DstPort)
		}
		ethernet := ll.(*layers.Ethernet)
		// can add length and type
		printPacket = fmt.Sprintf("%vSource MAC: %v|Destination Mac: %v|", printPacket, ethernet.SrcMAC, ethernet.DstMAC)
		fmt.Println(printPacket)
	}
}

// Layers
// Ethernet
// IPv4
// IPv6
// UDP
// TCP
// DNS
// Payload
