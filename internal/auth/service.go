package nynAuth

import (
	"fmt"
	"net"
	"os"

	nynCrypto "nyn/internal/crypto"

	"github.com/charmbracelet/log"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/text/encoding/simplifiedchinese"
)

type logger struct {
	server *log.Logger
	client *log.Logger
}

func newLogger() *logger {
	var l logger
	l.server = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: true,
		Prefix:          "h3c",
	})
	l.client = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: true,
		Prefix:          "nyn",
	})
	return &l
}

// DeviceInterface defines methods for sending and receiving packets.
type DeviceInterface interface {
	Send(l ...gopacket.SerializableLayer) ([]byte, error)
	SetBPFFilter(f string, a ...any) (string, error)
	GetLocalMAC() net.HardwareAddr
	GetTargetMAC() net.HardwareAddr
	SetTargetMAC(mac net.HardwareAddr)
	GetIfaceName() string
	GetIP() net.IP
	Stop()
}

type AuthService struct {
	Device    DeviceInterface
	h3cInfo   nynCrypto.H3CInfo
	h3cBuffer []byte
	username  string
	password  string
	retry     int
}

func New(device DeviceInterface, h3cInfo nynCrypto.H3CInfo, username string, password string, retry int) *AuthService {
	return &AuthService{
		Device:   device,
		h3cInfo:  h3cInfo,
		username: username,
		password: password,
		retry:    retry,
	}
}

func (as *AuthService) Stop() error {
	_, error := as.SendSignOffPacket()
	as.Device.Stop()
	return error
}

func (as *AuthService) HandlePacket(packet gopacket.Packet) error {
	l := newLogger()
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ethPacket, _ := ethLayer.(*layers.Ethernet)

	if eapLayer := packet.Layer(layers.LayerTypeEAP); eapLayer != nil {
		eapPacket, _ := eapLayer.(*layers.EAP)
		l.server.Info("eap", "Id", eapPacket.Id, "Type", eapPacket.Type, "Code", eapPacket.Code)

		if as.Device.GetTargetMAC() == nil {
			as.Device.SetTargetMAC(ethPacket.SrcMAC)
			as.Device.SetBPFFilter("ether src %s and ether proto 0x888E", ethPacket.SrcMAC)
			as.SendFirstIdentity(eapPacket.Id)
			l.client.Info("answered first identity")
			return nil // return func to avoid proceed to following logic
		}

		switch eapPacket.Code {
		case layers.EAPCodeSuccess:
			l.client.Info("suc (^_^)")
		case layers.EAPCodeFailure:
			if eapPacket.Type == EAPTypeMD5Failed {
				// Convet GBK Message from Server to UTF-8
				failMsgSize := eapPacket.TypeData[0]
				failMsg, _ := simplifiedchinese.GBK.NewDecoder().Bytes(eapPacket.TypeData[1 : failMsgSize-1])
				l.server.Error(fmt.Sprintf("%s", failMsg))
				l.client.Fatal("fal (o.0)")
			} else {
				if as.retry > 0 {
					as.retry = as.retry - 1
					l.client.Error("an error occured qwq! remaining", "retry", as.retry)
					as.SendStartPacket()
				} else {
					l.client.Fatal("retry ran out, maybe we should re-auth?")
				}
			}
		case layers.EAPCodeRequest:
			l.server.Info("asking for something...")
		case EAPCodeH3CData:
			if eapPacket.TypeData[H3CIntegrityChanllengeHeader-1] == 0x35 {
				// Generate ChallangeResponse
				var err error
				as.h3cBuffer, err = as.h3cInfo.ChallangeResponse(
					eapPacket.TypeData[H3CIntegrityChanllengeHeader:][:H3CIntegrityChanllengeLength])
				if err != nil {
					l.client.Error("failed to set integrity")
					l.client.Error(err)
				} else {
					l.client.Info("integrity set")
				}
			}
		default:
			l.client.Warn("unknow eap", "Code", eapPacket.Code)
		}

		switch eapPacket.Type {
		case layers.EAPTypeNone:
			l.server.Info("suc/fal")
		case layers.EAPTypeOTP:
			as.SendResponseMD5(eapPacket.Id, eapPacket.Contents)
			l.client.Info("answered md5otp")
		case layers.EAPTypeIdentity:
			as.SendIdentity(eapPacket.Id, as.h3cBuffer)
			l.client.Info("answered identity")
		default:
			l.client.Warn("unknow eap", "Type", eapPacket.Type)
		}
	}

	return nil
}
