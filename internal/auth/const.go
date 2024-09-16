package nynAuth

import (
	"net"
)

type EAPType uint8
type EAPCode uint8

var (
	EAPCodeH3CData EAPCode = 10

	EAPTypeMD5       EAPType = 4
	EAPTypeAllocated EAPType = 7
	EAPTypeAvaliable EAPType = 20

	ResponseVersionHeader      = []byte{0x06, 0x07}
	ResponseMD5SignatureHeader = []byte{byte(MD5SignatureLength)}
)

const (
	EAPResponseHeaderLength  int = 5
	EAPRequestHeaderLength   int = 5
	MD5SignatureHeaderLength int = 1
	MD5SignatureLength       int = 16
)

var (
	MultcastAddr  = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
	BroadcastAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)
