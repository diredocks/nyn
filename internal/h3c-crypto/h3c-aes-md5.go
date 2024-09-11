package h3cCrypto

import (
	"crypto/aes"
	"crypto/cipher"
	//"crypto/md5"
	"fmt"
)

type DictInfo struct {
	Offset byte
	Length byte
	Index  []byte
}

func ChallangeResponse(challenge []byte, h3c_info H3CInfo) []byte {
	decryptedChallenge := aes128Decryption(challenge, h3c_info.AesKey, h3c_info.AesIV)
	first16Bytes := decryptedChallenge[:16]
	last16Bytes := decryptedChallenge[len(decryptedChallenge)-16:]

	info := DictInfo{
		Index:  decryptedChallenge[:4],
		Offset: decryptedChallenge[4],
		Length: decryptedChallenge[5],
	}
	dictExtraction := extractFromDict(info, h3c_info.Dict)
	dictExtractionMD5 := ComputeMD5Hash(dictExtraction)

	deDecryptedChallenge := aes128Decryption(last16Bytes, dictExtractionMD5, h3c_info.AesIV)
	responseChallenge := append(first16Bytes, deDecryptedChallenge...)

	info = DictInfo{
		Index:  deDecryptedChallenge[10:14],
		Offset: deDecryptedChallenge[14],
		Length: deDecryptedChallenge[15],
	}
	dictExtraction2 := extractFromDict(info, h3c_info.Dict)
	responseMask := append(dictExtraction, dictExtraction2...)

	for i, _ := range responseChallenge {
		if i == len(responseMask) {
			break
		}
		responseChallenge[i] = responseMask[i]
	}

	responseChallenge = ComputeMD5Hash(responseChallenge)
	responseChallenge = append(responseChallenge, ComputeMD5Hash(responseChallenge)...)
	return responseChallenge
}

func extractFromDict(info DictInfo, h3c_dict map[[4]byte][]byte) []byte {
	key := [4]byte(info.Index)
	value, exists := h3c_dict[key]
	if !exists {
		panic(fmt.Sprintf("The key: %x doesn't exists in the key-map(h3c_dict)", key))
	}
	extraction := value[info.Offset : info.Offset+info.Length]
	return extraction
}

func aes128Decryption(cipherhex []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(cipherhex)%aes.BlockSize != 0 {
		panic("Ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainhex := make([]byte, len(cipherhex))
	mode.CryptBlocks(plainhex, cipherhex)
	// Optionally remove padding
	//plainhex = pkcs7Unpad(plainhex)
	return plainhex
}

// pkcs7Unpad removes PKCS7 padding
func pkcs7Unpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}
