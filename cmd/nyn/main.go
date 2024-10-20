package main

import (
	"flag"
	"fmt"
	nynAuth "nyn/internal/auth"
	nynCrypto "nyn/internal/crypto"
	nynDevice "nyn/internal/device"

	"os"
	"os/signal"

	"github.com/BurntSushi/toml"
	"github.com/charmbracelet/log"
)

type Config struct {
	General struct {
		ScheduleCallback bool `toml:"schedule_callback"`
	} `toml:"general"`
	Crypto struct {
		WinVer    string `toml:"win_ver"`
		ClientVer string `toml:"client_ver"`
		ClientKey string `toml:"client_key"`
	} `toml:"crypto"`
	Auth []struct {
		User     string `toml:"user"`
		Password string `toml:"password"`
		Device   string `toml:"device"`
	} `toml:"auth"`
}

type authInterface struct {
	Auth   *nynAuth.AuthService
	Device *nynDevice.Device
}

func main() {
	// load and parse config.toml
	filePath := flag.String("config", "config.toml", "Path to the config")
	flag.Parse()
	if *filePath == "" {
		log.Fatal("Please provide a config path using the -config flag")
	}

	var config Config
	// Decode the TOML file into the config struct
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Fatalf("Error decoding TOML file: %v", err)
	}

	// check weekend holiday etc...
	/*
	  today := time.Now()
	  tomorrow := today.AddDate(0, 0, 1)
	  // should be some error handling here
	  _, isTodayHoliday, _ := isHoliday(today, conf.HolidayJson)
	  _, isTomorrowHoliday, _ := isHoliday(tomorrow, conf.HolidayJson)
	  if !isTomorrowHoliday && !isWeekend(tomorrow) {
	    log.Println("Schedule close at 12 PM")
	  } // what if weekend is work day? maybe network stays? never mind
	  if !isWeekend(today) && !isTodayHoliday {
	    log.Println("Schedule start at 08 AM")
	  }
	*/

	cryptoInfo := nynCrypto.H3CInfoDefault
	cryptoInfo.WinVer = []byte(config.Crypto.WinVer)
	//cryptoInfo.Version = []byte(config.Crypto.ClientVer)
	cryptoInfo.Key = []byte(config.Crypto.ClientKey)

	var authServices []nynAuth.AuthService
	for _, user := range config.Auth {
		var device *nynDevice.Device
		device, err := nynDevice.New(user.Device)
		if err != nil {
			log.Fatal(err)
		}

		authService := nynAuth.New(device,
			cryptoInfo,
			user.User,
			user.Password)
		if err = device.Start(authService); err != nil {
			log.Fatal(err)
		}
		authService.SendStartPacket()
		authServices = append(authServices, *authService)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	for {
		select {
		case sig := <-sigs:
			_ = sig
			fmt.Printf("\r")
			log.Info("bye!")
			for _, eachService := range authServices {
				eachService.Stop()
			}
			return
		}
	}
}
