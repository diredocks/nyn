package nynAuth

import (
	"github.com/gopacket/gopacket/layers"
)

func (as *AuthService) SendStartPacket() ([]byte, error) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       as.Device.GetLocalMAC(),
		DstMAC:       BroadcastAddr,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapolLayer := &layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeStart,
	}
	return as.Device.Send(ethLayer, eapolLayer)
}

func (as *AuthService) SendSignOffPacket() ([]byte, error) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       as.Device.GetLocalMAC(),
		DstMAC:       MultcastAddr,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapolLayer := &layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeLogOff,
	}
	return as.Device.Send(ethLayer, eapolLayer)
}

func (as *AuthService) SendFirstIdentity(eapId uint8) ([]byte, error) {
	response := ResponseBase{
		H3CInfo:  as.h3cInfo,
		Username: []byte(as.username),
		Password: []byte(as.password),
	}
	responseData := response.MarshalToBytes()
	ethLayer := &layers.Ethernet{
		SrcMAC:       as.Device.GetLocalMAC(),
		DstMAC:       as.Device.GetTargetMAC(),
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapolLayer := &layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
		Length:  uint16(len(responseData) + EAPResponseHeaderLength),
	}
	eapLayer := &layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       eapId,
		Type:     layers.EAPTypeIdentity,
		TypeData: responseData,
		Length:   eapolLayer.Length,
	}
	return as.Device.Send(ethLayer, eapolLayer, eapLayer)
}

func (as *AuthService) SendResponseMD5(eapId uint8, eapContent []byte) ([]byte, error) {
	response := ResponseMD5{
		ResponseBase: ResponseBase{
			Username: []byte(as.username),
			Password: []byte(as.password),
		},
		EapId:      eapId,
		EapContent: eapContent,
	}
	responseData := response.MarshalToBytes()
	ethLayer := &layers.Ethernet{
		SrcMAC:       as.Device.GetLocalMAC(),
		DstMAC:       as.Device.GetTargetMAC(),
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapolLayer := &layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
		Length:  uint16(len(responseData) + EAPResponseHeaderLength),
	}
	eapLayer := &layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       eapId,
		Type:     layers.EAPTypeOTP,
		TypeData: responseData,
		Length:   eapolLayer.Length,
	}
	return as.Device.Send(ethLayer, eapolLayer, eapLayer)
}
