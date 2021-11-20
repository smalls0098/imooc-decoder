package decoder

import (
	"container/list"
)

type info struct {
	content       string
	encryptTable  []string
	keyTables     *list.List
	info          string
	anonymousInfo []rune
	resultInfo    []rune
}

var dis = []rune{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1,
	-1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
	-1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
	13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1,
	-1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
	37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
	-1, -1, -1, -1, -1,
}

//Decrypt imooc m3u8数据解密
func Decrypt(encrypt string) []byte {
	data := info{
		content: encrypt,
	}
	content := data.content
	key := content[len(content)-4:]

	u := make([]rune, 4)
	for k, v := range key {
		u[len(key)-1-k] = v % 4
	}

	d := make([]string, 4)
	for i := 0; i < 4; i++ {
		d[i] = content[u[i]+1 : u[i]+2]
		content = content[0:u[i]+1] + content[u[i]+2:]
	}
	data.encryptTable = d
	keyTables := list.New()
	for _, v := range d {
		if v == "q" || v == "k" {
			l := content[len(content)-12:]
			keyTables.PushFront(l)
			content = content[:len(content)-12]
		}
	}
	//设置key
	data.keyTables = keyTables
	data.info = content
	data.anonymousInfo = anonymous(content)
	data.resultInfo = data.anonymousInfo
	a := ""
	for _, v := range data.resultInfo {
		a += string(v)
	}
	for i := 0; i < len(data.encryptTable); i++ {
		v := data.encryptTable[i]
		if v == "q" || v == "k" {
			tempEle := data.keyTables.Back()
			if key, ok := tempEle.Value.(string); ok {
				data.keyTables.Remove(tempEle)
				if v == "q" {
					data.resultInfo = q(data.resultInfo, key)
				}
				if v == "k" {
					data.resultInfo = k(data.resultInfo, key)
				}
			}
		} else {
			if v == "h" {
				data.resultInfo = h(data.resultInfo)
			}
			if v == "m" {
				data.resultInfo = m(data.resultInfo)
			}
		}
	}
	res := make([]byte, 0)
	for _, v := range data.resultInfo {
		res = append(res, byte(v))
	}
	return res
}

func anonymous(info string) []rune {
	length := len(info)
	o := 0
	var s []rune

	var e rune = -1
	var r rune = -1
	var n rune = 0
	var i rune = 0

	for o < length {
		for true {
			e = dis[255&info[o]]
			o++
			if !(o < length && e == -1) {
				break
			}
		}
		if e == -1 {
			break
		}

		for true {
			r = dis[255&info[o]]
			o++
			if !(o < length && r == -1) {
				break
			}
		}
		if r == -1 {
			break
		}

		s = append(s, e<<2|(48&r)>>4)

		for true {
			n = rune(255 & info[o])
			o++
			if n == 61 {
				return s[:]
			}
			n = dis[n]
			if !(o < length && n == -1) {
				break
			}
		}
		if n == -1 {
			break
		}
		s = append(s, (15&r)<<4|(60&n)>>2)

		for true {
			i = rune(255 & info[o])
			o++
			if i == 61 {
				return s[:]
			}
			i = dis[i]
			if !(o < length && i == -1) {
				break
			}
		}
		if i == -1 {
			break
		}
		s = append(s, (3&n)<<6|i)
	}
	return s[:]
}

func q(str []rune, key string) []rune {
	a := make([]rune, len(str))
	for i := 0; i < len(str); i++ {
		a[i] = 0
	}
	keyLen := len(key)
	for k := range str {
		o := k % keyLen
		i := str[k]
		a[k] = i ^ rune(key[o])
	}
	return a
}

func k(str []rune, key string) []rune {
	s := make([]rune, len(str))
	for i := 0; i < len(str); i++ {
		s[i] = 0
	}
	for k, v := range str {
		s[k] = v
	}
	n := 0
	var i rune = 0
	o := 0
	r := 0
	for r < len(str) {
		o = int(s[r] % 5)
		if o != 0 {
			if o != 1 && r+o < len(s) {
				i = s[r+1]
				n = r + 2
				s[r+1] = s[r+o]
				s[o+r] = i
				r = r + o + 1
				if r-2 > n {
					for n < r-2 {
						keyLen := len(key)
						z := n % keyLen
						s[n] = rune(uint8(s[n]) ^ key[z])
						n++
					}
				}
			}
		}
		r++
	}
	for k := range str {
		s[k] = rune(uint8(s[k]) ^ key[k%len(key)])
	}
	return s
}

func h(n []rune) []rune {
	a := make([]rune, len(n))
	for i := 0; i < len(n); i++ {
		a[i] = 0
	}
	for k, v := range n {
		a[k] = v
	}
	var r = 0
	for r < len(a) {
		i := int(a[r] % 3)
		if i != 0 {
			if r+i < len(a) {
				o := a[r+1]
				a[r+1] = a[r+i]
				a[r+i] = o
				r = r + i + 1
			}
		}
		r++
	}
	return a
}

func m(n []rune) []rune {
	var o = 0
	var r = 0
	var a = 0
	for r < len(n) {
		o = int(n[r] % 2)
		if o > 0 {
			r++
		}
		a++
		r++
	}
	s := make([]rune, a)
	r = 0
	i := 0
	for r < len(n) {
		o = int(n[r] % 2)
		if o > 0 {
			s[i] = n[r]
			i++
			r++
		} else {
			s[i] = n[r]
			i++
		}
		r++
	}
	return s
}
