package inynCrypto

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	//"time"
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

func GetEncryptedClientVersion(h3c_info H3CInfo) []byte {
	encryptedClientVersion := make([]byte, 20)
	//random := uint32(time.Now().Unix()) // Can be any 32-bit integer
	random := rand.Uint32()
	randomKey := fmt.Sprintf("%08x", random) // Generate RandomKey as a string
	// First round of XOR using RandomKey as the key to encrypt the first 16 bytes
	copy(encryptedClientVersion[:16], h3c_info.Version)
	xor(encryptedClientVersion, []byte(randomKey))
	// Append the 4-byte random value in network byte order to make 20 bytes total
	binary.BigEndian.PutUint32(encryptedClientVersion[16:], random)
	// Second round of XOR using H3C_KEY as the key to encrypt the first 20 bytes
	xor(encryptedClientVersion, h3c_info.Key[:])
	return encryptedClientVersion
}

func GetBasedEncryptedClientVersion(h3c_info H3CInfo) []byte {
	basedEncryptedClientVersion := make([]byte, 28)
	base64.StdEncoding.Encode(basedEncryptedClientVersion, GetEncryptedClientVersion(h3c_info))
	return basedEncryptedClientVersion
}

func GetEncryptedWindowsVersion(h3c_info H3CInfo) []byte {
	encryptedWindowsVersion := make([]byte, 20)
	copy(encryptedWindowsVersion, h3c_info.WinVer)
	xor(encryptedWindowsVersion, h3c_info.Key[:])
	return encryptedWindowsVersion
}

func ComputeMD5Hash(data []byte) []byte {
	hash := md5.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func xor(data []byte, key []byte) {
	dlen := len(data)
	klen := len(key)
	// Process the data slice in forward order
	for i := 0; i < dlen; i++ {
		data[i] ^= key[i%klen]
	}
	// Process the data slice in reverse order
	for i, j := dlen-1, 0; j < dlen; i, j = i-1, j+1 {
		data[i] ^= key[j%klen]
	}
}
