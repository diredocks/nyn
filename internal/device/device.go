package nynDevice

import (
	"fmt"
	"net"
	nynAuth "nyn/internal/auth"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

type Device struct {
	TargetMAC net.HardwareAddr
	localMAC  net.HardwareAddr
	ifaceName string
	handle    *pcap.Handle
	done      chan int
}

func getAddr(ifaceName string) (net.HardwareAddr, net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, err
	}
	return iface.HardwareAddr, nil, nil // TODO: Fill in the ip declearation
}

func (d *Device) SetBPFFilter(f string, a ...any) (string, error) {
	f = fmt.Sprintf(f, a...)
	if err := d.handle.SetBPFFilter(f); err != nil {
		return "", fmt.Errorf("Error setting BPF filter: %v", err)
	}
	return f, nil
}

func New(ifaceName string) (*Device, error) {
	mac, _, err := getAddr(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, ifaceName)
	}

	return &Device{
		localMAC:  mac,
		ifaceName: ifaceName,
		done:      make(chan int),
	}, nil
}

func (d *Device) Start(as *nynAuth.AuthService) error {
	var err error
	d.handle, err = pcap.OpenLive(d.ifaceName, 1600, false, time.Millisecond)
	if err != nil {
		return err
	}
	if _, err := d.SetBPFFilter("ether dst %s and ether proto 0x888E", d.localMAC); err != nil {
		return err
	}
	packetSource := gopacket.NewPacketSource(d.handle, d.handle.LinkType())

	go func() {
		for {
			select {
			case <-d.done:
				return
			case packet := <-packetSource.Packets():
				as.HandlePacket(packet)
			}
		}
	}()
	return nil
}

func (d *Device) Stop() {
	close(d.done)
	if d.handle != nil {
		d.handle.Close()
	}
}

func (d *Device) Send(l ...gopacket.SerializableLayer) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	bufferOptions := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, bufferOptions, l...); err != nil {
		return nil, err
	}

	if err := d.handle.WritePacketData(buffer.Bytes()); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (d *Device) GetLocalMAC() net.HardwareAddr {
	return d.localMAC
}

func (d *Device) GetTargetMAC() net.HardwareAddr {
	return d.TargetMAC
}
func (d *Device) SetTargetMAC(mac net.HardwareAddr) {
	d.TargetMAC = mac
}
