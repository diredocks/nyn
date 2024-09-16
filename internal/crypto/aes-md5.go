package nynCrypto

import (
	"fmt"
)

type DictInfo struct {
	Offset byte
	Length byte
	Index  []byte
}

func (i *H3CInfo) ChallangeResponse(challenge []byte) ([]byte, error) {
	decryptedChallenge, err := aes128Decryption(challenge, i.AesKey, i.AesIV)
	if err != nil {
		return nil, err
	}
	first16Bytes := decryptedChallenge[:16]
	last16Bytes := decryptedChallenge[len(decryptedChallenge)-16:]

	info := DictInfo{
		Index:  decryptedChallenge[:4],
		Offset: decryptedChallenge[4],
		Length: decryptedChallenge[5],
	}
	dictExtraction, err := extractFromDict(info, i.Dict)
  if err != nil {
    return nil, err
  }
	dictExtractionMD5 := ComputeMD5Hash(dictExtraction)

	var deDecryptedChallenge []byte
	deDecryptedChallenge, err = aes128Decryption(last16Bytes, dictExtractionMD5, i.AesIV)
	if err != nil {
		return nil, err
	}

	responseChallenge := append(first16Bytes, deDecryptedChallenge...)

	info = DictInfo{
		Index:  deDecryptedChallenge[10:14],
		Offset: deDecryptedChallenge[14],
		Length: deDecryptedChallenge[15],
	}
	dictExtraction2, err := extractFromDict(info, i.Dict)
  if err != nil {
    return nil, err
  }
	responseMask := append(dictExtraction, dictExtraction2...)

	for i, _ := range responseChallenge {
		if i == len(responseMask) {
			break
		}
		responseChallenge[i] = responseMask[i]
	}

	responseChallenge = ComputeMD5Hash(responseChallenge)
	responseChallenge = append(responseChallenge, ComputeMD5Hash(responseChallenge)...)
	return responseChallenge, nil
}

func extractFromDict(info DictInfo, h3c_dict map[[4]byte][]byte) ([]byte, error) {
	key := [4]byte(info.Index)
	value, exists := h3c_dict[key]
	if !exists {
		return nil, fmt.Errorf("The key: %x doesn't exists in the key-map(h3c_dict)", key)
	}
	extraction := value[info.Offset : info.Offset+info.Length]
	return extraction, nil
}
