package decoder

import (
	"testing"
)

func TestDecrypt(t *testing.T) {
	res := Decrypt("自己复制过来测试")
	t.Log(res)
}
