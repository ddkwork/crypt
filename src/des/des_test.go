package des

import (
	"testing"

	"github.com/ddkwork/golibrary/stream"

	"github.com/stretchr/testify/assert"
)

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
