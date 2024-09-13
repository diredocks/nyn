package inynDevice

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"inyn-go/internal/crypto"
	"inyn-go/internal/packets"
)

// sendPacket sends a packet through the specified interface
func (d *Device) sendPacket(l ...gopacket.SerializableLayer) ([]byte, error) {
	// Serialize the layers and payload
	err := gopacket.SerializeLayers(d.buffer, d.bufferOptions, l...)
	if err != nil {
		return nil, fmt.Errorf("could not serialize packet: %v", err)
	}

	// Send the packet
	err = d.handle.WritePacketData(d.buffer.Bytes())
	if err != nil {
		return nil, fmt.Errorf("could not send packet: %v", err)
	}

	return d.buffer.Bytes(), nil
}

func (d *Device) sendStartPacket() ([]byte, error) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       d.LocalMAC,
		DstMAC:       BroadcastAddr,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapolLayer := &layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeStart,
	}
	return d.sendPacket(ethLayer, eapolLayer)
}

func (d *Device) sendLogOffPacket() ([]byte, error) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       d.LocalMAC,
		DstMAC:       MultcastAddr,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapolLayer := &layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeLogOff,
	}
	return d.sendPacket(ethLayer, eapolLayer)
}

func (d *Device) sendFirstIdentityPacket(eapId uint8) ([]byte, error) {
	response := inynPackets.ResponseFirstIdentity{
		ResponseBase: inynPackets.ResponseBase{
			Username: []byte(""), // fill in Username
		},
	}
	responseData := response.MarshalToBytes(inynCrypto.H3C_INFO)
	ethLayer := &layers.Ethernet{
		SrcMAC:       d.LocalMAC,
		DstMAC:       d.TargetMAC,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapolLayer := &layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
		Length:  uint16(len(responseData) + 5),
		// 5 represent the size of EAP header
		// Code(1)+Id(1)+Length(2)+Type(1)
	}
	eapLayer := &layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       eapId,
		Type:     layers.EAPTypeIdentity,
		TypeData: responseData,
		Length:   eapolLayer.Length,
	}
	return d.sendPacket(ethLayer, eapolLayer, eapLayer)
}

func (d *Device) sendResponseMD5(eapId uint8, md5Challenge []byte) ([]byte, error) {
	response := inynPackets.ResponseMD5{
		ResponseBase: inynPackets.ResponseBase{
			Username: []byte(""), // fill in Username
			Password: []byte(""), // fill in Password
		},
		EapId:        eapId,
		MD5Challenge: md5Challenge,
	}
	responseData := response.MarshalToBytes(inynCrypto.H3C_INFO)
	ethLayer := &layers.Ethernet{
		SrcMAC:       d.LocalMAC,
		DstMAC:       d.TargetMAC,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapolLayer := &layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
		Length:  uint16(len(responseData) + 5),
		// 5 represent the size of EAP header
		// Code(1)+Id(1)+Length(2)+Type(1)
	}
	eapLayer := &layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       eapId,
		Type:     layers.EAPTypeOTP,
		TypeData: responseData,
		Length:   eapolLayer.Length,
	}
	return d.sendPacket(ethLayer, eapolLayer, eapLayer)
}

func (d *Device) sendIdentityPacket(eapId uint8, md5Challenge []byte) ([]byte, error) {
	response := inynPackets.ResponseMD5{
		ResponseBase: inynPackets.ResponseBase{
			Username: []byte(""), // fill in Username
			Password: []byte(""), // fill in Password
		},
		EapId:        eapId,
		MD5Challenge: md5Challenge,
	}
	responseData := response.MarshalToBytes(inynCrypto.H3C_INFO)
	ethLayer := &layers.Ethernet{
		SrcMAC:       d.LocalMAC,
		DstMAC:       d.TargetMAC,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapolLayer := &layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
		Length:  uint16(len(responseData) + 5),
		// 5 represent the size of EAP header
		// Code(1)+Id(1)+Length(2)+Type(1)
	}
	eapLayer := &layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       eapId,
		Type:     layers.EAPTypeOTP,
		TypeData: responseData,
		Length:   eapolLayer.Length,
	}
	return d.sendPacket(ethLayer, eapolLayer, eapLayer)
}
