package nynCrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"fmt"
)

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

func aes128Decryption(cipherhex []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherhex)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("Ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainhex := make([]byte, len(cipherhex))
	mode.CryptBlocks(plainhex, cipherhex)
	// Optionally remove padding
	//plainhex = pkcs7Unpad(plainhex)
	return plainhex, nil
}

// pkcs7Unpad removes PKCS7 padding
func pkcs7Unpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}
