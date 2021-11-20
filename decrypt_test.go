package decoder

import (
	"testing"
)

func TestDecrypt(t *testing.T) {
	res := Decrypt("m3u8 data info")
	t.Log(res)
}
