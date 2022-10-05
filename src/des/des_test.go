package des

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDes(t *testing.T) {
	r := New()
	src := "1122334455667788"
	key := "1122334455667788"
	dst := r.Encrypt(src, key)
	assert.Equal(t, "cd09bc4876ac0f2b", dst.HexString())

	d := r.Decrypt(dst.Bytes(), key)
	assert.Equal(t, "1122334455667788", d.HexString())

}

// TestMarshal the crypto implementation
func TestDes1(t *testing.T) {
	println("TestMarshal DES")

	key := to_bytes("1122334455667788")
	msg := to_bytes("1122334455667788")

	subkeys := expand(key)
	crypt := des_encrypt(msg, subkeys)
	clear := des_decrypt(crypt, subkeys)

	pretty("Key", key)
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
