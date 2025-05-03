package rsa

import (
	"math/big"
	"slices"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
)

type (
	Interface interface { // todo add output integer and hex method
		Encrypt(src *stream.Buffer, n, e string) (dst *stream.Buffer)
		Decrypt(src *stream.Buffer, n, e, d string) (dst *stream.Buffer)
		CalcD(e, p, q string) *stream.Buffer // 计算私钥
		D() *big.Int
		SetD(d string)
		Factorization(src *stream.Buffer) (dst *stream.Buffer) // 因式分解
	}
	object struct {
		p *big.Int
		q *big.Int
		c *big.Int
		d *big.Int
		e *big.Int
		n *big.Int
		m string
	}
)

func (o *object) SetP(p string) {
	setString, b := new(big.Int).SetString(p, 16)
	if !b {
		return
	}
	o.p = setString
}

func (o *object) SetQ(q string) {
	setString, b := new(big.Int).SetString(q, 16)
	if !b {
		return
	}
	o.q = setString
	return
}

func (o *object) Factorization(src *stream.Buffer) (dst *stream.Buffer) { panic("implement me") }

func (o *object) C() *big.Int { return o.c }

func (o *object) SetC(c string) {
	setString, b := new(big.Int).SetString(c, 16)
	if !b {
		return
	}
	o.c = setString
}

func (o *object) SetD(d string) {
	setString, b := new(big.Int).SetString(d, 16)
	if !b {
		return
	}
	o.d = setString
}

func (o *object) D() *big.Int { return o.d }

func (o *object) E() *big.Int { return o.e }

func (o *object) SetE(e string) {
	setString, b := new(big.Int).SetString(e, 16)
	if !b {
		return
	}
	o.e = setString
}

func (o *object) N() *big.Int { return o.n }

func (o *object) SetN(n string) {
	if n != "" {
		setString, b := new(big.Int).SetString(n, 16)
		if !b {
			return
		}
		o.n = setString
		return
	}
	o.n = new(big.Int).Mul(o.p, o.q)
}

func (o *object) M() string     { return o.m }
func (o *object) SetM(m string) { o.m = m }

func (o *object) init() {
	//*o = object{}                 //reset
	p := create_random_prime(512) // c440da3f63fa0e2b32f18d7b76e9b3d78b1303c3f09ea6a6ba92da461363c48f765f9ec7ed4308060b7c01ef7cd76fb126f4bc94976644880b458fc0fe9a7193
	mylog.Info("p", p.String())
	q := create_random_prime(512) // fd76d3567f9e0fac965edde9cb7e77d046e6587c69cb9fe1872ade55fae5c76fd983ab80a4d1427b85ccbe8c8e33a5a2459cd6bcff45338e74607cc9dabb704f
	mylog.Info("q", q.String())
	o.n = new(big.Int).Mul(p, q) // c24f2f9902871e462a4c6649ef405c2e4fd19fdb416ec2bbf50d8b6915ecc000fee3fce62dd6e9bfff44f30087bf5a933759a7a5f2592c5a3acf5b1d7530c3f16b9806a34a8526026d03e57901a49a3e2523ee8e960174fd488e647999470a75bdaa993d42a3727f61738b749bbaba7023e646234e6b3aea2d8babe547ba5c5d
	mylog.Info("o.n", o.n.String())
	o.e = big.NewInt(0x10001)
	mylog.Info("o.e", o.e.String()) // 10001
	// Create phi: (p-1)*(q-1)
	one := big.NewInt(1)
	p_minus_1 := new(big.Int).Sub(p, one)
	q_minus_1 := new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(p_minus_1, q_minus_1)
	o.d = new(big.Int).ModInverse(o.e, phi)
	mylog.Info("o.d", o.d.String())
}

func fnCheck(src ...string) bool {
	return !slices.Contains(src, "")
}

func (o *object) Encrypt(src *stream.Buffer, n, e string) (dst *stream.Buffer) {
	if !fnCheck(src.String(), n, e) {
		return
	}
	o.SetN(n)
	o.SetE(e)
	m := new(big.Int).SetBytes(src.Bytes())
	o.c = new(big.Int).Exp(m, o.e, o.n)
	return stream.NewBuffer(o.c.Bytes())
}

func (o *object) Decrypt(src *stream.Buffer, n, e, d string) (dst *stream.Buffer) {
	if !fnCheck(src.String(), n, e, d) {
		return
	}
	o.SetN(n)
	o.SetE(e)
	o.SetD(d)
	o.c = new(big.Int).SetBytes(src.Bytes())
	m := new(big.Int).Exp(o.c, o.d, o.n)
	return stream.NewBuffer(m.Bytes())
}

func (o *object) CalcD(e, p, q string) *stream.Buffer {
	if !fnCheck(p, q, e) {
		return nil
	}
	o.SetE(e)
	o.SetP(p)
	o.SetQ(q)

	// Dp, Dq *big.Int // D mod (P-1) (or mod Q-1)
	// Qinv   *big.Int // Q^-1 mod P

	one := big.NewInt(1)
	Dp := new(big.Int).Sub(o.p, one)
	Dq := new(big.Int).Sub(o.q, one)
	phi := new(big.Int).Mul(Dp, Dq)
	Qinv := new(big.Int).Div(Dq, o.p)

	mylog.Info("one", one.String())
	mylog.Info("Dp", Dp.String())
	mylog.Info("Dq", Dq.String())
	mylog.Info("phi", phi.String())
	mylog.Info("Qinv", Qinv.String())

	o.d = new(big.Int).ModInverse(o.e, phi)
	return stream.NewBuffer(o.d.Bytes())
}

var Default = New()

func New() Interface { return &object{} }
