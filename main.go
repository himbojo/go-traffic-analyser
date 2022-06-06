package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device      string = "wlo1"
	snaplen     int32  = 1600
	promiscuous bool   = true
	err         error
	timeout     time.Duration = pcap.BlockForever
	handle      *pcap.Handle
)

// Hello returns a greeting for the named person.
func main() {
	getDevices()
	startLiveCapture()
}

func getDevices() {
	// get devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// display device info
	fmt.Printf("Devices:\n\n")
	for _, device := range devices {
		fmt.Println("Name: ", device.Name)
		fmt.Println("Interface: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- - Address: ", address.IP)
		}
		fmt.Println()
	}
}

func startLiveCapture() {
	// open an interface
	handle, err = pcap.OpenLive(device, snaplen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// take handler and set as the packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// process packets
		handlePacket(packet)
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
			printPacket = fmt.Sprintf("%vsIPv4:%-37vdIPv4:%-37v", printPacket, ipv4.SrcIP, ipv4.DstIP)
		}
		if nlipv6 != nil {
			ipv6 := nlipv6.(*layers.IPv6)
			printPacket = fmt.Sprintf("%vsIPv6:%-37vdIPv6:%-37v", printPacket, ipv6.SrcIP, ipv6.DstIP)
		}
		if tltcp != nil {
			tcp := tltcp.(*layers.TCP)
			// can add tcp message types
			printPacket = fmt.Sprintf("%vsPort:%-8ddPort:%-8dProto:TCP  ", printPacket, tcp.SrcPort, tcp.DstPort)
		}
		if tludp != nil {
			udp := tludp.(*layers.UDP)
			printPacket = fmt.Sprintf("%vsPort:%-8ddPort:%-8dProto:UDP  ", printPacket, udp.SrcPort, udp.DstPort)
		}
		ethernet := ll.(*layers.Ethernet)
		// can add length and type
		printPacket = fmt.Sprintf("%vsMAC:%-21vdMAC:%v", printPacket, ethernet.SrcMAC, ethernet.DstMAC)
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
