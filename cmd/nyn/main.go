package main

import (
	"fmt"
	"log"

	"os"
	"os/signal"
	"syscall"

	"nyn/internal/auth"
	"nyn/internal/crypto"
	"nyn/internal/device"
)

func main() {
  log.Println("nyn - how's it doing? :D")

	device, err := nynDevice.New("enp1s0")
	authService := nynAuth.New(device, nynCrypto.H3CInfoDefault, "", "")

	if err = device.Start(authService); err != nil {
		log.Fatal("Failed to intialize device: ", err)
	}

	authService.SendStartPacket() // not that elegent, but works

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case sig := <-sigs:
			fmt.Printf("\r")
			log.Printf("nyn - signal: %s. bye!", sig)
      authService.SendSignOffPacket() // same as above
			device.Stop()
			return
		}
	}
}
