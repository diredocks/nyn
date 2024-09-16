package nynCrypto

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
)

type H3CInfo struct {
	AesKey  []byte
	AesIV   []byte
	WinVer  []byte
	Version []byte
	Key     []byte
	Dict    map[[4]byte][]byte
}

func (i *H3CInfo) EncryptedClientVersion() []byte {
	encryptedClientVersion := make([]byte, 20)
	//random := uint32(time.Now().Unix()) + 2 // Can be any 32-bit integer
	random := rand.Uint32()
	randomKey := fmt.Sprintf("%08x", random) // Generate RandomKey as a string
	// First round of XOR using RandomKey as the key to encrypt the first 16 bytes
	copy(encryptedClientVersion, i.Version)
	xor(encryptedClientVersion[:16], []byte(randomKey))
	// Append the 4-byte random value in network byte order to make 20 bytes total
	binary.BigEndian.PutUint32(encryptedClientVersion[16:], random)
	// Second round of XOR using H3C_KEY as the key to encrypt the first 20 bytes
	xor(encryptedClientVersion, i.Key[:])
	return encryptedClientVersion
}

func (i *H3CInfo) BasedEncryptedClientVersion() []byte {
	basedEncryptedClientVersion := make([]byte, 28)
	base64.StdEncoding.Encode(basedEncryptedClientVersion, i.EncryptedClientVersion())
	return basedEncryptedClientVersion
}

func (i *H3CInfo) EncryptedWindowsVersion() []byte {
	encryptedWindowsVersion := make([]byte, 20)
	copy(encryptedWindowsVersion, i.WinVer)
	xor(encryptedWindowsVersion, i.Key[:])
	return encryptedWindowsVersion
}
