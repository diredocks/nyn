package main

import (
	"flag"
	"fmt"
	nynAuth "nyn/internal/auth"
	nynCrypto "nyn/internal/crypto"
	nynDevice "nyn/internal/device"
	"os"
	"os/signal"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/charmbracelet/log"
	"github.com/gopacket/gopacket/pcap"
)

type Config struct {
	General struct {
		ScheduleCallback bool `toml:"schedule_callback"`
		TimeOut          int  `toml:"timeout"`
		Retry            int  `toml:"retry"`
	} `toml:"general"`
	Crypto struct {
		WinVer    string `toml:"win_ver"`
		ClientVer string `toml:"client_ver"`
		ClientKey string `toml:"client_key"`
	} `toml:"crypto"`
	Auth []struct {
		User                string `toml:"user"`
		Password            string `toml:"password"`
		Device              string `toml:"device"`
		HardwareDescription string `toml:"hardware_description"`
	} `toml:"auth"`
}

type authInterface struct {
	Auth   *nynAuth.AuthService
	Device *nynDevice.Device
}

func main() {
	mode := flag.String("mode", "", "Use -mode info to see hardware description")
	filePath := flag.String("config", "config.toml", "Path to the config")
	flag.Parse()
	// Show hardware_description to make Windows users happy
	if *mode == "info" {
		devices, error := pcap.FindAllDevs()
		if error != nil {
			log.Fatal(error)
		}
		for _, device := range devices {
			log.Info("Found",
				"device", device.Name,
				"hardware_description", device.Description)
		}
		return
	}
	// load and parse config.toml
	if *filePath == "" {
		log.Fatal("Please provide a config path using the -config flag")
	}

	var config Config
	// Decode the TOML file into the config struct
	if _, err := toml.DecodeFile(*filePath, &config); err != nil {
		log.Fatalf("Error decoding TOML file: %v", err)
	}

	cryptoInfo := nynCrypto.H3CInfoDefault
	cryptoInfo.WinVer = []byte(config.Crypto.WinVer)
	// cryptoInfo.Version = []byte(config.Crypto.ClientVer)
	cryptoInfo.Key = []byte(config.Crypto.ClientKey)

	var authServices []nynAuth.AuthService
	for _, user := range config.Auth {
		var device *nynDevice.Device
		device, err := nynDevice.New(user.Device, user.HardwareDescription)
		if err != nil {
			log.Fatal(err)
		}

		authService := nynAuth.New(device,
			cryptoInfo,
			user.User,
			user.Password,
			config.General.Retry)
		if err = device.Start(authService); err != nil {
			log.Fatal(err)
		}
		authService.SendStartPacket()
		authServices = append(authServices, *authService)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	timeout := time.After(time.Duration(config.General.TimeOut) * time.Second)

	for {
		select {
		case sig := <-sigs:
			_ = sig
			fmt.Printf("\r")
			for _, eachService := range authServices {
				eachService.Stop()
				log.Warn("Stopped", "device", eachService.Device.GetIfaceName())
			}
			log.Info("bye!")
			return
		case <-timeout:
			noResponseLen := 0
			for _, eachService := range authServices {
				if eachService.Device.GetTargetMAC() == nil {
					log.Error("No server response from", "device", eachService.Device.GetIfaceName())
					noResponseLen = noResponseLen + 1
				}
			}
			if len(authServices) == noResponseLen {
				log.Fatal("No active interface, exiting...")
			}
		}
	}
}
