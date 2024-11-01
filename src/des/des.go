package des

import (
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
)

var (
	encryptCount = 0
	decryptCount = 0
)

func Encrypt[T stream.Type](src, key T) (dst *stream.Buffer) {
	s := stream.NewBuffer(src)
	k := stream.NewBuffer(key)
	encryptCount++
	defer func() {
		mylog.Struct(EncryptInfo{
			Src:   s.Bytes(),
			Key:   k.Bytes(),
			Dst:   dst.Bytes(),
			Count: encryptCount,
		})
	}()
	s.CheckDesBlockSize()
	k.CheckDesBlockSize()
	subKeys := expand(k.Bytes())
	return stream.NewBuffer(des_encrypt(s.Bytes(), subKeys))
}

func Decrypt[T stream.Type](src, key T) (dst *stream.Buffer) {
	s := stream.NewBuffer(src)
	k := stream.NewBuffer(key)
	decryptCount++
	defer func() {
		mylog.Struct(DecryptInfo{
			Src:   s.Bytes(),
			Key:   k.Bytes(),
			Dst:   dst.Bytes(),
			Count: decryptCount,
		})
	}()
	s.CheckDesBlockSize()
	k.CheckDesBlockSize()
	subKeys := expand(k.Bytes())
	return stream.NewBuffer(des_decrypt(s.Bytes(), subKeys))
}

type DecryptInfo struct {
	Src   []byte
	Key   Key
	Dst   []byte
	Count int
}

type EncryptInfo struct {
	Src   []byte
	Key   Key
	Dst   []byte
	Count int
}

type Key []byte

func (k Key) String() string { // 让mylog.Struct统一慢慢反射，一劳永逸，这就是接口的力量
	return string(k)
}
