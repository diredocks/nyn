package main

import (
	"flag"
	"fmt"
	"log"
	/*
	  "time"

	*/
	"github.com/BurntSushi/toml"
	"nyn/internal/auth"
	"nyn/internal/crypto"
	"nyn/internal/device"
	"os"
	"os/signal"
	"syscall"
)

// Config represents the structure of your TOML file.
type Config struct {
	General struct {
		ScheduleCallback bool `toml:"schedule_callback"`
	} `toml:"general"`
	Encryption struct {
		DecryptID string `toml:"decrypt_id"`
	} `toml:"encryption"`
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
	  }*/

	var interfaces []authInterface
	for _, each := range config.Auth {
		var device *nynDevice.Device
		device, err := nynDevice.New(each.Device)
		if err != nil {
			log.Fatal("Failed to intialize device: ", err)
		}

		authService := nynAuth.New(device, nynCrypto.H3CInfoDefault, each.User, each.Password)
		if err = device.Start(authService); err != nil {
			log.Fatal("Failed to intialize device: ", err)
		}
    authService.SendStartPacket()

		interfaces = append(interfaces, authInterface{
			Auth:   authService,
			Device: device})
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case sig := <-sigs:
			fmt.Printf("\r")
			log.Printf("nyn - signal: %s. bye!", sig)
      for _, interfaced := range interfaces {
        interfaced.Auth.SendSignOffPacket()
        interfaced.Device.Stop()
      }
			return
		}
	}
}
