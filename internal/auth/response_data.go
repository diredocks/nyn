package nynAuth

import (
	//"net"
	"nyn/internal/crypto"
)

type ResponseBase struct {
	H3CInfo  nynCrypto.H3CInfo
	Username []byte
	Password []byte
}

func (r *ResponseBase) MarshalToBytes() []byte {
	data := ResponseVersionHeader
	data = append(data, r.H3CInfo.BasedEncryptedClientVersion()...)
	data = append(data, "  "...)
	data = append(data, r.Username...)
	return data
}

type ResponseMD5 struct {
	ResponseBase
	EapId      uint8
	Request    []byte
	EapContent []byte
}

func (r *ResponseMD5) MarshalToBytes() []byte {
	header := ResponseMD5SignatureHeader
	buffer := []byte{r.EapId}
	buffer = append(buffer, r.Password...)
	buffer = append(buffer, r.EapContent[EAPRequestHeaderLength+MD5SignatureHeaderLength:]...)
	buffer = nynCrypto.ComputeMD5Hash(buffer)
	data := append(header, buffer...)
	data = append(data, r.Username...)
	return data
}