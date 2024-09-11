// This is supposed to be the main program of Inyn

package main

import (
    "fmt"
    "log"
    "net"
    "os"
    "time"
    "os/signal"
    "syscall"
    "github.com/gopacket/gopacket"
    "github.com/gopacket/gopacket/pcap"
    "github.com/gopacket/gopacket/layers"
)

func getMACAddress(ifaceName string) (net.HardwareAddr, error) {
    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        return nil, err
    }
    return iface.HardwareAddr, nil
}

func main() {
    ifaceName := "enp1s0" // Change this to the interface you are using

    // Get the MAC address of the interface
    mac, err := getMACAddress(ifaceName)
    if err != nil {
        log.Fatal("Could not get MAC address: ", err)
    }
    fmt.Println("MAC Address: ", mac.String())

    // Open the device for capturing
    handle, err := pcap.OpenLive(ifaceName, 1600, false, time.Millisecond) // pcap.BlockForever would block this thing up
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    // Set BPF filter to capture only EAP packets destined for the host
    bpfFilter := fmt.Sprintf("ether dst %s and ether proto 0x888E", mac)
    if err := handle.SetBPFFilter(bpfFilter); err != nil {
        log.Fatal("Error setting BPF filter: ", err)
    }
    fmt.Println("BPF filter set: ", bpfFilter)

    // Create a packet source to capture packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    // Set up a channel to receive OS signals
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    timeout := time.After(10 * time.Second)
    var targetMAC net.HardwareAddr
    fmt.Println("Capturing packets... Press Ctrl+C to stop.")

    // Use select to handle both packet reception and signal interrupts
    for {
        select {
        case sig := <-sigs:
            fmt.Printf("Received signal: %s. Exiting...\n", sig)
            return

        case <-timeout:
            if targetMAC == nil {
                fmt.Println("No packets received in the initial period. Exiting...")
                return
            }
            // Reset the timeout to allow continued capture if a packet is eventually received
            timeout = time.After(10 * time.Second)
            
        case packet := <-packetSource.Packets():
            // Log packet information
            fmt.Println("Captured packet:")
            fmt.Printf("Packet Length: %d bytes\n", len(packet.Data()))
            fmt.Println("Packet Data: ", packet.Data())

            // Check if the packet contains an Ethernet layer
            if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
                ethPacket, _ := ethLayer.(*layers.Ethernet)
                fmt.Println("Source MAC: ", ethPacket.SrcMAC)
                fmt.Println("Destination MAC: ", ethPacket.DstMAC)
                // If this is the first packet, set the target MAC address
                if targetMAC == nil {
                    targetMAC = ethPacket.SrcMAC
                    fmt.Printf("First packet received. Source MAC set to: %s\n", targetMAC)
                    
                    // Update the BPF filter to capture EAP packets from this specific source MAC
                    updatedFilter := fmt.Sprintf("ether src %s and ether proto 0x888E", targetMAC)
                    if err := handle.SetBPFFilter(updatedFilter); err != nil {
                        log.Fatal("Error updating BPF filter: ", err)
                    }
                    fmt.Println("Updated BPF filter set: ", updatedFilter)
                }
            }
            // Check if it contains an EAPOL (EAP over LAN) layer
            if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
                fmt.Println("EAP Packet captured!")
            }
        }
    }
}
