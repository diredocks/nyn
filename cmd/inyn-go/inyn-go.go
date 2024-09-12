package main

import (
	"fmt"
	"inyn-go/internal/device"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Create a new capture instance with mac filled in
	device, err := inynDevice.NewDevice("enp1s0")
	if err != nil {
		log.Fatal("Could not get MAC address: ", err)
	}
	log.Println("MAC Address: ", device.LocalMAC)

	// Start capturing packets
	go device.Start()

	// Set up a channel to receive OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	timeout := time.After(10 * time.Second)

	// Wait for a signal to stop
	for {
		select {

		case sig := <-sigs:
			fmt.Print("\r")
			log.Printf("Received stop signal: %s. Exiting...\n", sig)
			device.Stop()
			return

		case <-timeout:
			if device.TargetMAC == nil {
				log.Println("No packets receive in the initial period, Exiting...")
				device.Stop()
				return
			}
			timeout = time.After(10 * time.Second)
		}

	}

}
