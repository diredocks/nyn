package nynAuth

import (
	"net"
	nynCrypto "nyn/internal/crypto"
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
	header := []byte{byte(MD5SignatureLength)}
	buffer := []byte{r.EapId}
	buffer = append(buffer, r.Password...)
	buffer = append(buffer, r.EapContent[EAPRequestHeaderLength+MD5SignatureHeaderLength:]...)
	buffer = nynCrypto.ComputeMD5Hash(buffer)
	data := append(header, buffer...)
	data = append(data, r.Username...)
	return data
}

type ResponseIdentity struct {
	ResponseBase
	IP                net.IP
	ChallengeResponse []byte
}

func (r *ResponseIdentity) MarshalToBytes() []byte {
	data := ResponseIdentityHeader
	data = append(data, r.ChallengeResponse...)
	data = append(data, ResponseIPHeader...)
	data = append(data, r.IP...)
	data = append(data, r.ResponseBase.MarshalToBytes()...)
	return data
}
