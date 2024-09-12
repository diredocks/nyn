package inynDevice

import (
	"fmt"
	"log"
	"net"
	"time"
	//"os"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// Capture handles the packet capturing process
type Device struct {
	LocalMAC      net.HardwareAddr
	TargetMAC     net.HardwareAddr
	packetSource  *gopacket.PacketSource
	handle        *pcap.Handle
	buffer        gopacket.SerializeBuffer
	bufferOptions gopacket.SerializeOptions
	ifaceName     string
	done          chan int
}

func getMACAddress(ifaceName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	return iface.HardwareAddr, nil
}

// New creates a new Capture instance
func NewDevice(ifaceName string) (*Device, error) {
	// Get the MAC address of the interface
	mac, err := getMACAddress(ifaceName)
	if err != nil {
    return nil, err
	}

	return &Device{
		done:      make(chan int),
		ifaceName: ifaceName,
		LocalMAC:  mac,
		buffer:    gopacket.NewSerializeBuffer(),
		bufferOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
	}, nil
}

func (d *Device) setBPFFilter(filter string, a ...any){
  bpfFilter := fmt.Sprintf(filter, a...)
  if err := d.handle.SetBPFFilter(bpfFilter); err != nil {
    log.Fatal("Error setting BPF filter: ", err)
  }
  log.Println("BPF filter set: ", bpfFilter)
}

// Start begins packet capturing in a separate goroutine
func (d *Device) Start() {
	var err error
	d.handle, err = pcap.OpenLive(d.ifaceName, 1600, false, time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}

  d.setBPFFilter("ether dst %s and ether proto 0x888E", d.LocalMAC)
	d.packetSource = gopacket.NewPacketSource(d.handle, d.handle.LinkType())

  // We are ready to take off lol
  if err := d.sendStartPacket(); err != nil {
    log.Fatal("Failed to send StartPacket: ", err)
  }
  log.Println("StartPacket sent!")

  // NOTE: This Goroutine loops receiving packets and handles exit signal
	for {
		select {
		case <-d.done:
			return
		case packet := <-d.packetSource.Packets():
			// Handle packet processing
			log.Println("Captured packet:")
			log.Printf("Packet Length: %d bytes\n", len(packet.Data()))
			log.Println("Packet Data: ", packet.Data())
			// Further packet processing can be done here
			d.handlePacket(packet)
		}
	}
}

// handleSendPacket processes the received packet and sends a response if needed
func (d *Device) handlePacket(packet gopacket.Packet) {
	// Check for Ethernet layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		ethPacket, _ := ethLayer.(*layers.Ethernet)
		// Fill in the TargetMAC and update the BPFFilter
		if d.TargetMAC == nil {
			d.TargetMAC = ethPacket.SrcMAC
			log.Printf("First packet received. TargetMAC set to: %s\n", d.TargetMAC)
      d.setBPFFilter("ether src %s and ether proto 0x888E", d.TargetMAC)
		}
	}

	// Check if it contains an EAPOL (EAP over LAN) layer
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		eapolPacket, _ := eapolLayer.(*layers.EAPOL)
		log.Println("EAPOL Packet captured! Type: ", eapolPacket.Type)
	}

	if eapLayer := packet.Layer(layers.LayerTypeEAP); eapLayer != nil {
		eapPacket, _ := eapLayer.(*layers.EAP)
    log.Printf("EAP Packet captured! Type: %d Code: %d Id: %d \n", eapPacket.Type, eapPacket.Code, eapPacket.Id)
	}
}

// Stop stops the packet capturing process
func (d *Device) Stop() {
	close(d.done)
	if d.handle != nil {
		d.handle.Close()
	}
	log.Println("Capture stopped.")
}
