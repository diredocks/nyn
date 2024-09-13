package inynPackets

import (
	//"github.com/google/gopacket"
	"inyn-go/internal/crypto"
	"net"
)

type ResponseBase struct {
	Username []byte
	Password []byte
	IP       net.IP
}

type ResponseFirstIdentity struct {
	ResponseBase
}

func (r ResponseBase) MarshalToBytes(h3c_info inynCrypto.H3CInfo) []byte {
	res := []byte{0x06, 0x07}                                                 // indicate version field start
	res = append(res, inynCrypto.GetBasedEncryptedClientVersion(h3c_info)...) // add the encrypted client version code
	res = append(res, "  "...)                                                // add two spaces to the slice
	res = append(res, r.Username...)                                          // add username in the end
	return res
}

type ResponseAvailable struct {
	ResponseBase
	Proxy byte
}

func (r ResponseAvailable) MarshalToBytes(h3c_info inynCrypto.H3CInfo) []byte {
	res := []byte{r.Proxy}                   // report if proxy used
	res = append(res, []byte{0x15, 0x04}...) // indicate ip field start
	res = append(res, (r.IP[:])...)          // add ip
	res = append(res, r.ResponseBase.MarshalToBytes(h3c_info)...)
	return res
}

type ResponseIdentity struct {
	ResponseBase
	Challange [32]byte // Challange Sequence
}

func (r ResponseIdentity) MarshalToBytes(h3c_info inynCrypto.H3CInfo) []byte {
	res := []byte{0x16, 0x20} // indicate AES_MD5 Challange Response start
	res = append(res, inynCrypto.ChallangeResponse(r.Challange[:], h3c_info)...)
	res = append(res, []byte{0x15, 0x04}...) // indicate ip field start
	res = append(res, (r.IP[:])...)          // add ip
	res = append(res, r.ResponseBase.MarshalToBytes(h3c_info)...)
	return res
}

type ResponseMD5 struct {
	ResponseBase
	EapId        uint8
	MD5Challenge []byte
}

func (r ResponseMD5) MarshalToBytes(h3c_info inynCrypto.H3CInfo) []byte {
	size := []byte{16}     // md5 sig length is 16
	buf := []byte{r.EapId} // EapId + Username + MD5 generated from Server(ResponseMD5)
	buf = append(buf, r.Password...)
	buf = append(buf, r.MD5Challenge...)
	// extract md5 sig from request
	// which is the last 16 bits in request
	buf = inynCrypto.ComputeMD5Hash(buf)
	res := append(size, buf...)
	res = append(res, r.Username...)
	return res
}

type ResponsePassword struct {
	ResponseBase
}

type ResponseNotification struct {
	Version []byte
	WinVer  []byte
}
