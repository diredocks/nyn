package inynDevice

import (
  "fmt"
  "github.com/gopacket/gopacket"
  "github.com/gopacket/gopacket/layers"
)

// sendPacket sends a packet through the specified interface
func (d *Device) sendPacket(l ...gopacket.SerializableLayer) error {
	/*
	   // Build the Ethernet layer
	   ethLayer := &layers.Ethernet{
	       SrcMAC:       srcMAC,
	       DstMAC:       dstMAC,
	       EthernetType: layers.EthernetTypeEAPOL,
	   }*/

	// Serialize the layers and payload
	err := gopacket.SerializeLayers(d.buffer, d.bufferOptions, l...)
	if err != nil {
		return fmt.Errorf("could not serialize packet: %v", err)
	}

	// Send the packet
	err = d.handle.WritePacketData(d.buffer.Bytes())
	if err != nil {
		return fmt.Errorf("could not send packet: %v", err)
	}

	return nil
}

func (d *Device) sendStartPacket() error {
  ethLayer := &layers.Ethernet {
    SrcMAC: d.LocalMAC,
    DstMAC: MultcastAddr,
	  EthernetType: layers.EthernetTypeEAPOL,
  }
  eapolLayer := &layers.EAPOL {
    Version: 0x01,
    Type:    layers.EAPOLTypeStart,
  }
  if err := d.sendPacket(ethLayer, eapolLayer); err != nil {
    return err
  }
  return nil
}
