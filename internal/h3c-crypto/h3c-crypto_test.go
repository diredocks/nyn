package h3cCrypto

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestGetEncryptedWindowsVersion(t *testing.T) {
	want, _ := hex.DecodeString("0b1f7c7f114a3d27647c7c55110579284c4c2879")
	got := GetEncryptedWindowsVersion(H3C_INFO)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("got %x want %x", got, want)
	}
}
