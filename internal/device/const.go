package inynDevice

import (
  "net"
)

type EAPType uint8
type EAPCode uint8

const (
	EAPCodeH3CData EAPCode = 10

	EAPTypeMD5       EAPType = 4
	EAPTypeAllocated EAPType = 7
	EAPTypeAvaliable EAPType = 20
)

var (
  MultcastAddr  = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
  BroadcastAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)
