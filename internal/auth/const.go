package nynAuth

import (
	"net"

	"github.com/gopacket/gopacket/layers"
)

// type EAPType uint8
// type EAPCode uint8
var (
	EAPCodeH3CData layers.EAPCode = 10

	EAPTypeMD5             layers.EAPType = 4
	EAPTypeAllocated       layers.EAPType = 7
	EAPTypeAvaliable       layers.EAPType = 20
	EAPTypeMD5Failed       layers.EAPType = 9
	EAPTypeInactiveKickoff layers.EAPType = 8

	ResponseVersionHeader  = []byte{0x06, 0x07}
	ResponseIdentityHeader = []byte{0x16, 0x20}
	ResponseIPHeader       = []byte{0x15, 0x04}
)

const (
	EAPResponseHeaderLength      int = 5
	EAPRequestHeaderLength       int = 5
	EAPRequestHeadernoCodeLength int = 4
	MD5SignatureHeaderLength     int = 1
	MD5SignatureLength           int = 16
	H3CIntegrityChanllengeHeader int = 4
	H3CIntegrityChanllengeLength int = 32
)

var (
	MultcastAddr  = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
	BroadcastAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	BridgeAddr    = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
)
