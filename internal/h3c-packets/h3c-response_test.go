package h3cPackets

import (
	//"reflect"
  "fmt"
	"testing"
  "inyn-go/internal/h3c-crypto"
)

func TestMarshalToBytes(t *testing.T) {
  res_fi := ResponseFirstIdentity {
    ResponseBase: ResponseBase {
      Username: []byte("helloworld"),
    },
  }
  res := res_fi.MarshalToBytes(h3cCrypto.H3C_INFO)
  fmt.Println(res, len(res))

  res_md5 := ResponseMD5 {
    EapId: 1,
    Username: []byte("helloworld"),
    RequestMD5: [16]byte{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
  }
  res = res_md5.MarshalToBytes(h3cCrypto.H3C_INFO)
  fmt.Println(res, len(res))
	/*if !reflect.DeepEqual(want, got) {
		t.Errorf("got %x want %x", got, want)
	}*/
}
