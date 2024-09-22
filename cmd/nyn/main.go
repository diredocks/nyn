package main

import (
	"flag"
	"fmt"
	"log"

	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/BurntSushi/toml"

	"nyn/internal/auth"
	"nyn/internal/crypto"
	"nyn/internal/device"
)

type Config struct {
	Username string
	Password string
	Device   string
}

func main() {

	filePath := flag.String("config", "config.toml", "Path to the config")
	flag.Parse()
	if *filePath == "" {
		log.Fatal("Please provide a config path using the -config flag")
	}

	tomlData, err := ioutil.ReadFile(*filePath)
	if err != nil {
		log.Fatalf("Failed to read the file: %v", err)
	}

	var conf Config
	_, err = toml.Decode(string(tomlData), &conf)

	var device *nynDevice.Device
	device, err = nynDevice.New(conf.Device)
	if err != nil {
		log.Fatal("Failed to intialize device: ", err)
	}
	authService := nynAuth.New(device, nynCrypto.H3CInfoDefault, conf.Username, conf.Password)

	if err = device.Start(authService); err != nil {
		log.Fatal("Failed to intialize device: ", err)
	}

	log.Println("nyn - how's it doing? :D")
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
