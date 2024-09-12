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
	if dataSent, err := d.sendPacket(ethLayer, eapolLayer); err != nil {
		return nil, err
	} else {
		return dataSent, nil
	}
}

func (d *Device) sendFirstIdentityPacket(eapId uint8) ([]byte, error) {
	response := inynPackets.ResponseFirstIdentity{
		ResponseBase: inynPackets.ResponseBase{
			Username: []byte(""),
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

func (d *Device) sendResponseMD5(eapId uint8, requestPacket []byte) ([]byte, error) {
	response := inynPackets.ResponseMD5{
		EapId:      eapId,
		Username:   []byte(""),
		RequestMD5: requestPacket[len(requestPacket)-16:],
		// extract md5 sig from request
		// which is the last 16 bits in request
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
