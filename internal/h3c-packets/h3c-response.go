package h3cPackets

import (
	//"github.com/google/gopacket"
  "inyn-go/internal/h3c-crypto"
)

type EAPType uint8
type EAPCode uint8

const (
  EAPCodeH3CData    EAPCode = 10
  
  EAPTypeMD5        EAPType = 4
  EAPTypeAllocated  EAPType = 7
  EAPTypeAvaliable  EAPType = 20
)

type ResponseBase struct {
  Username []byte
}

func (r ResponseBase) MarshalToBytes(h3c_info h3cCrypto.H3CInfo) []byte {
  res := []byte{0x06, 0x07} // indicate version field start
  res = append(res, h3cCrypto.GetBasedEncryptedClientVersion(h3c_info)...) // add the encrypted client version code
  res = append(res, "  "...) // add two spaces to the slice
  res = append(res, r.Username...) // add username in the end
  return res
}

type ResponseAvailable struct {
  ResponseBase
  IP [4]byte
  Proxy byte
}
func (r ResponseAvailable) MarshalToBytes(h3c_info h3cCrypto.H3CInfo) []byte {
  res := []byte{r.Proxy} // report if proxy used
  res = append(res, []byte{0x15, 0x04}...) // indicate ip field start
  res = append(res, (r.IP[:])...) // add ip
  res = append(res, r.ResponseBase.MarshalToBytes(h3c_info)...)
  return res
}

type ResponseIdentity struct {
  ResponseBase
  Challange [32]byte // Challange Sequence
  IP [4]byte
}
func (r ResponseIdentity) MarshalToBytes(h3c_info h3cCrypto.H3CInfo) []byte {
  res := []byte{0x16, 0x20} // indicate AES_MD5 Challange Response start
  res = append(res, h3cCrypto.ChallangeResponse(r.Challange[:], h3c_info)...)
  res = append(res, []byte{0x15, 0x04}...) // indicate ip field start
  res = append(res, (r.IP[:])...) // add ip
  res = append(res, r.ResponseBase.MarshalToBytes(h3c_info)...)
  return res
}

type ResponseFirstIdentity struct {
  ResponseBase
}

type ResponseMD5 struct {
  EapId byte
  Username []byte
  RequestMD5 [16]byte
}
func (r ResponseMD5) MarshalToBytes(h3c_info h3cCrypto.H3CInfo) []byte {
  size := []byte{16}; // the buff size should be 16
  buf := []byte{r.EapId} // EapId + Username + MD5 generated from Server(ResponseMD5)
  buf = append(buf, r.Username...)
  buf = append(buf, r.RequestMD5[:]...)
  buf = h3cCrypto.ComputeMD5Hash(buf)
  res := append(size, buf...)
  res = append(res, r.Username...)
  return res
}

type ResponsePassword struct {
  Password  []byte
  Username  []byte
}

type ResponseNotification struct {
  Version   []byte
  WinVer    []byte
}
