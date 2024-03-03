package aes

import (
	"github.com/ddkwork/golibrary/safeType"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAes(t *testing.T) {
	src := safeType.HexString("1122334455667788")
	key := safeType.HexString("1122334455667788")
	dst := Encrypt(src, key)
	assert.Equal(t, safeType.HexString("6df46f5c40d62cd9889fa57d698754e4"), dst.HexString())

	d := Decrypt(dst.HexString(), key)
	assert.Equal(t, safeType.HexString("11223344556677880000000000000000"), d.HexString())
}

// TestMarshal the AES implementation
// This should output the original message, encrypt it, then decrypt it again
func TestName(t *testing.T) {
	println("TestMarshal AES crypto")

	key := to_bytes("1122334455667788")
	msg := to_bytes("1122334455667788")

	crypt := encrypt(msg, key)
	clear := decrypt(crypt[0:], key)

	pretty("Key", key)
	pretty("Message", msg)
	pretty("Encrypted", crypt[0:])
	pretty("Decrypted", clear[0:])
}

//func main() {
//  println("TestMarshal AES crypto");
//
//  key := to_bytes("12345612345612345612345612345612")
//  msg := to_bytes("abcdefabcdefabcdefabcdefabcdefab")
//
//  crypt := encrypt(msg,key)
//  clear := decrypt(crypt[0:],key)
//
//  pretty("Key", key)
//  pretty("Message", msg)
//  pretty("Encrypted", crypt[0:])
//  pretty("Decrypted", clear[0:])
//}
