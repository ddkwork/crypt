package des

import (
	"testing"

	"github.com/ddkwork/golibrary/stream"
	"github.com/stretchr/testify/assert"
)

func TestBug(t *testing.T) {
	e := EncryptInfo{
		Src:   []byte{0xca, 0x43, 0xf3, 0x40, 0x4b, 0xfa, 0x6b, 0xb9},
		Key:   []byte{0x75, 0x6a, 0x2e, 0x6b, 0x2a, 0x2d, 0x46, 0x64}, //"uj.k*-Fd"
		Dst:   []byte{0xd8, 0xbf, 0x1d, 0x11, 0x62, 0x9f, 0xd9, 0x21},
		Count: 0x2 | 2,
	}
	dst := Encrypt(e.Src, e.Key)
	assert.Equal(t, e.Dst, dst.Bytes())

	// d := Decrypt(dst.HexString(), stream.HexString(key))
	// assert.Equal(t, stream.HexString("1122334455667788"), d.HexString())
}

func TestDes(t *testing.T) {
	src := "1122334455667788"
	key := "1122334455667788"
	dst := Encrypt(stream.HexString(src), stream.HexString(key))
	assert.Equal(t, stream.HexString("cd09bc4876ac0f2b"), dst.HexString())

	d := Decrypt(dst.HexString(), stream.HexString(key))
	assert.Equal(t, stream.HexString("1122334455667788"), d.HexString())
}

// TestMarshal the crypto implementation
func TestDes1(t *testing.T) {
	println("TestMarshal DES")

	key := to_bytes("1122334455667788")
	msg := to_bytes("1122334455667788")

	subkeys := expand(key)
	crypt := des_encrypt(msg, subkeys)
	clear := des_decrypt(crypt, subkeys)

	pretty("Label", key)
	pretty("Message", msg)
	pretty("Encrypted", crypt)
	pretty("Decrypted", clear)
}

func TestDes3(t *testing.T) {
	println("\r\nTestMarshal Triple-DES")
	k3d := to_bytes("11223344556677898798794535213544")
	m3d := to_bytes("1234567890ABCDEF")
	e3d := tripledes_encrypt(m3d, k3d)
	d3d := tripledes_decrypt(e3d, k3d)
	pretty("Encrypted (should be 3A-3A-CE-65-0D-B3-BB-DC)", e3d)
	pretty("Decrypted (should be 12-34-56-78-90-AB-CD-EF)", d3d)
}
