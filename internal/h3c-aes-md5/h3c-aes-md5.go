package h3cAuth

import (
	"crypto/aes"
  "crypto/md5"
	"crypto/cipher"
  "fmt"
)

type DataInfo struct {
  Offset byte
  Length byte
  Index  []byte
}

func Fuck(){
	ciphertext := []byte{0xcf, 0xfe, 0x64, 0x73,
                       0xd5, 0x73, 0x3b, 0x1f,
                       0x9e, 0x9a, 0xee, 0x1a,
                       0x6b, 0x76, 0x47, 0xc8,
                       0x9e, 0x27, 0xc8, 0x92,
                       0x25, 0x78, 0xc4, 0xc8,
                       0x27, 0x03, 0x34, 0x50,
                       0xb6, 0x10, 0xb8, 0x35}

  fmt.Printf("ojbk: %x\n", ChallangeResponse(ciphertext))
}

func ChallangeResponse(challenge []byte) []byte {
  decryptedChallenge := aes128Decryption(challenge, dumped_key, dumped_iv)
  first16Bytes := decryptedChallenge[:16]
  last16Bytes := decryptedChallenge[len(decryptedChallenge)-16:]

  info := DataInfo{
    Index: decryptedChallenge[:4],
    Offset: decryptedChallenge[4],
    Length: decryptedChallenge[5],
  }
  dictExtraction := extractFromDict(info, dumped_dict)
  dictExtractionMD5 := computeMD5Hash(dictExtraction)

  deDecryptedChallenge := aes128Decryption(last16Bytes, dictExtractionMD5, dumped_iv)
  responseChallenge := append(first16Bytes, deDecryptedChallenge...)

  info = DataInfo{
    Index: deDecryptedChallenge[10:14],
    Offset: deDecryptedChallenge[14],
    Length: deDecryptedChallenge[15],
  }
  dictExtraction2 := extractFromDict(info, dumped_dict)
  responseMask := append(dictExtraction, dictExtraction2...)

  for i, _ := range responseChallenge {
    if i == len(responseMask) {
      break
    }
    responseChallenge[i] = responseMask[i]
  }

  responseChallenge = computeMD5Hash(responseChallenge)
  responseChallenge = append(responseChallenge, computeMD5Hash(responseChallenge)...)
  return responseChallenge
}

func computeMD5Hash(data []byte) []byte {
    hash := md5.New()
    hash.Write(data)
    return hash.Sum(nil)
}

func extractFromDict(info DataInfo, dict map[[4]byte][]byte) []byte {
  index := [4]byte(info.Index)
  item, exists := dict[index]
  if !exists {
    panic(fmt.Sprintf("The key: %x doesn't exists in the dict, check h3c-const.go/dumped_dict", index))
  }
  extraction := item[info.Offset:info.Offset+info.Length]
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
