package rsa

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
)

func TestRsa(t *testing.T) {
	r := New()
	e := "10001"
	n := "703BF7A53D830F04A183A925211E322ADEB27404AEBD65607246934930A666B1"
	d := "172586F1613A4242A63CCD098746FEF96A7C930F2B357223F7DA700C26C85871"
	src := stream.NewBuffer("ddk")
	c := stream.HexString("0D28209417A9690EB52A9D83DCFF4F975BAB2F738136DE8CAED8C282703BC306")
	dst := r.Encrypt(src, n, e)
	assert.Equal(t, c, dst.HexStringUpper())

	m := r.Decrypt(stream.NewHexString(c), n, e, d)
	println(m.String())
}

func TestCalcD(t *testing.T) {
	e := "10001"
	p := "B926B1C30D63B1B5F38BCB981835DD73B71E0C879C2674737B8D1087726DE666DA7976E155F6631213F961B666E261CE8717FA78A90319093D50EA6E876208F3"
	q := "C27BBE3F2BECFD01F084979FFD46462A869C4C32955120DF59D1584FABA2D930E3243C9FDC878242440CFAA3287F71CFBEF29A2D73BDBFA237B5A7E406ABC9D5"
	r := New()
	d := r.CalcD(e, p, q) // hex mod ,todo add integer mod
	var dHexStr stream.HexString = "547F01800911D3E494875CFA30D70FB9B63A3A5C35EA15D9D5BFBB03CC467A4F04ED63E7AC0DD7B63A9A0DF7F9689C05F57ADD38E8AA72378B6303BE2BF645AC855A8F5D75E1D89B2F5D372884B0685A5F0E90D2EFB4024F6F2B023CCD4835308D24D9A1ACDF68F2F8CFDB4CC1560755F721021C73891E3BFED7ADD8EE35B3A9"
	assert.Equal(t, dHexStr, d.HexStringUpper())
}

func TestQinv(t *testing.T) {
	// Dp, Dq *big.Int // D mod (P-1) (or mod Q-1)
	// Qinv   *big.Int // Q^-1 mod P
	p := "B263990E7CD24052A66E21F91726E959D75B1A2BCCD270163BD9747D7DB760870057356F7F37190C848DF4A21DB94DE9DDF2605D152B82C75145B80B17799991"
	q := "E94B07ABEA21707FF5C38B381B394D694F42C847A63E8137CE571095CDF0F8C6FE52C77F479370569FC8E688BE6EFC0B25147AD64F4B826E37D224B30CFC4041"
	one := big.NewInt(1)
	Dp := new(big.Int).Sub(fromBase16(p), one)
	Dq := new(big.Int).Sub(fromBase16(q), one)
	phi := new(big.Int).Mul(Dp, Dq)
	Qinv := new(big.Int).Div(Dq, fromBase16(p))

	mylog.Info("one", one.String())
	mylog.Info("Dp", Dp.String())
	mylog.Info("Dq", Dq.String())
	mylog.Info("phi", phi.String())
	mylog.Info("Qinv", Qinv.String())
}

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

func fromBase16(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 16)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

// TestMarshal the RSA implementation
func TestName(t *testing.T) {
	println("TestMarshal RSA crypto")
	rand.Seed(int64(time.Nanosecond)) // Initialise the random generator

	// Generate P and Q, two big prime numbers
	println("Generating primes...")
	p := create_random_prime(512)
	q := create_random_prime(512)
	fmt.Printf("Prime p:\r\n %x\r\n", p)
	fmt.Printf("Prime q:\r\n %x\r\n", q)

	// Make n (the public key) now: n=p*q
	n := new(big.Int).Mul(p, q)
	fmt.Printf("Public key (n):\r\n %x\r\n", n)

	// Public exponent (always 0x10001)
	e := big.NewInt(0x10001)
	fmt.Printf("Exponent (e):\r\n %x\r\n", e)

	// Create phi: (p-1)*(q-1)
	one := big.NewInt(1)
	p_minus_1 := new(big.Int).Sub(p, one)
	q_minus_1 := new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(p_minus_1, q_minus_1)

	// Create the private key - it is the modular multiplicative inverse of e mod phi
	d := new(big.Int).ModInverse(e, phi)
	fmt.Printf("Secret key (d):\r\n %x\r\n", d)

	// Create a message randomly
	m := create_random_bignum(512)

	hexStr := hex.EncodeToString([]byte("ddk"))
	newM, b := new(big.Int).SetString(hexStr, 16)
	if !b {
		return
	}
	m = newM
	fmt.Printf("Message (m):\r\n %x\r\n", m)

	// Encrypt it: c = m^e mod n
	c := new(big.Int).Exp(m, e, n)
	fmt.Printf("Encrypt Crypto-text (c):\r\n %x\r\n", c)

	// Decrypt it: m = c^d mod n
	a := new(big.Int).Exp(c, d, n)
	fmt.Printf("Decrypt Message (c):\r\n %x\r\n", a)
}
