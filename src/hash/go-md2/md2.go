// Copyright 2012-2013 Huan Truong. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package md2 implements the MD2 hash algorithm as defined in RFC 1319.
package md2

import (
	//"crypto"
	"hash"
)

func init() {
	// crypto.RegisterHash(crypto.MD2, New)
}

// The size of an MD2 checksum in bytes.
const Size = 16

// The blocksize of MD2 in bytes.
const BlockSize = 16

const _Chunk = 16

var PI_SUBST = []uint8{
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
}

// digest represents the partial evaluation of a checksum.
type digest struct {
	digest [Size]byte   // the digest, Size
	state  [48]byte     // state, 48 ints
	x      [_Chunk]byte // temp storage buffer, 16 bytes, _Chunk
	nx     uint8        // how many bytes are there in the buffer
}

func (d *digest) Reset() {
	for i := range d.digest {
		d.digest[i] = 0
	}

	for i := range d.state {
		d.state[i] = 0
	}

	for i := range d.x {
		d.x[i] = 0
	}

	d.nx = 0
}

// New returns a new hash.Hash computing the MD2 checksum.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

// Write is the interface for IO Writer
func (d *digest) Write(p []byte) (nn int, err error) {
	// fmt.Printf("Getting %d bytes %x\n",len(p), p)
	nn = len(p)
	// d.len += uint64(nn)

	// If we have something left in the buffer
	if d.nx > 0 {
		n := uint8(len(p))

		// try to copy the rest n bytes free of the buffer into the buffer
		// then hash the buffer

		if (n + d.nx) > _Chunk {
			n = _Chunk - d.nx
		}

		for i := range n {
			// copy n bytes to the buffer
			d.x[d.nx+i] = p[i]
		}

		d.nx += n

		// if we have exactly 1 block in the buffer then hash that block
		if d.nx == _Chunk {
			block(d, d.x[0:_Chunk])
			d.nx = 0
		}

		p = p[n:]
	}

	imax := len(p) / _Chunk
	// For the rest, try hashing by the blocksize
	for range imax {
		block(d, p[:_Chunk])
		p = p[_Chunk:]
	}

	// Then stuff the rest that doesn't add up to a block to the buffer
	if len(p) > 0 {
		d.nx = uint8(copy(d.x[:], p))
		// fmt.Printf("Length of p = %d, copied %d.\n", len(p), d.nx)
	}

	return
}

func (d0 *digest) Sum(in []byte) []byte {
	// fmt.Printf("=== Got sum request ===\n")
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0

	// Padding.
	var tmp [_Chunk]byte
	// tmp := make([]byte, _Chunk, _Chunk)
	len := d.nx

	for i := range tmp {
		tmp[i] = _Chunk - len
	}

	// fmt.Printf("Calling block(%x) size %d for last block...\n", tmp, _Chunk-len)

	d.Write(tmp[0 : _Chunk-len])

	// At this state we should have nothing left in buffer
	if d.nx != 0 {
		panic("d.nx != 0")
	}

	d.Write(d.digest[0:16])

	// At this state we should have nothing left in buffer
	if d.nx != 0 {
		panic("d.nx != 0")
	}

	// fmt.Printf("=== Sum request done ===\n")
	// fmt.Printf("\n\n\n\n-------------------\n\n\n");
	return append(in, d.state[0:16]...)
}

func block(dig *digest, p []byte) {
	// fmt.Printf("block() digest (%x) updating with p(%x) len=%d\n", dig.digest, p, len(p))
	var t, i, j uint8
	t = 0

	for i = range 16 {
		dig.state[i+16] = p[i]
		dig.state[i+32] = p[i] ^ dig.state[i]
	}

	for i = range 18 {
		// fmt.Printf("t before: %d ", t)
		for j = range 48 {
			dig.state[j] = dig.state[j] ^ PI_SUBST[t]
			t = dig.state[j]
		}
		// fmt.Printf("t before: %d ", t)
		t = t + i
		// fmt.Printf("t after: %d\n", t)
	}

	// fmt.Printf("---------------\n")
	t = dig.digest[15]

	for i = range 16 {
		dig.digest[i] = dig.digest[i] ^ PI_SUBST[p[i]^t]
		t = dig.digest[i]
		// fmt.Printf("t after: %d\n", t)
	}

	// fmt.Printf(" --> Got digest = (%x)\n", dig.digest)
}
