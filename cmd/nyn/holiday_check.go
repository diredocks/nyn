package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"
)

// Holiday represents the structure of the holiday JSON.
type Holiday struct {
	Days []struct {
		Name     string `json:"name"`
		Date     string `json:"date"`
		IsOffDay bool   `json:"isOffDay"`
	} `json:"days"` // Nested Day struct
}

func getFieldNames(s interface{}) []string {
	val := reflect.ValueOf(s)
	typ := val.Type()

	var fieldNames []string
	for i := 0; i < val.NumField(); i++ {
		fieldNames = append(fieldNames, strings.ToLower(typ.Field(i).Name))
	}
	return fieldNames
}

func isWeekend(t time.Time) bool {
	day := t.Weekday()
	return day == time.Saturday || day == time.Sunday
}

// isHoliday checks if a given date is a holiday based on the provided holiday data.
func isHoliday(date time.Time, filePath string) (string, bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", false, fmt.Errorf("Error opening file:", err)
	}
	defer file.Close()
	var holidays Holiday
	err = json.NewDecoder(file).Decode(&holidays)
	if err != nil {
		return "", false, fmt.Errorf("Error parsing JSON:", err)
	}
	for _, day := range holidays.Days {
		holidayDate, err := time.Parse("2006-01-02", day.Date)
		if err != nil {
			continue // skip if date parsing fails
		}
		if holidayDate.Year() == date.Year() && holidayDate.YearDay() == date.YearDay() {
			return day.Name, day.IsOffDay, nil
		}
	}
	return "", false, nil
}
