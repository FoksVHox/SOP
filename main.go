package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"
	"strings"
)

const (
	Size  = 32
	chunk = 64
	init0 = 0x6A09E667
	init1 = 0xBB67AE85
	init2 = 0x3C6EF372
	init3 = 0xA54FF53A
	init4 = 0x510E527F
	init5 = 0x9B05688C
	init6 = 0x1F83D9AB
	init7 = 0x5BE0CD19
)

var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// digest represents the partial evaluation of a checksum.
type digest struct {
	h     [8]uint32
	x     [chunk]byte
	nx    int
	len   uint64
	is224 bool // mark if this digest is SHA-224
}

func New(input []byte) string {
	d := new(digest)
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
	d.nx = 0
	d.len = 0

	var p = input

	_, _ = d.write(p) // surpress error

	leng := d.len

	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if leng%64 < 56 {
		_, _ = d.write(tmp[0 : 56-leng%64])
	} else {
		_, _ = d.write(tmp[0 : 64+56-leng%64])
	}

	// Length in bits.
	leng <<= 3
	binary.BigEndian.PutUint64(tmp[:], leng)
	_, err := d.write(tmp[0:8])
	if err != nil {
		return "fejl 2"
	}

	fmt.Println(d.nx)
	if d.nx != 0 {
		panic(fmt.Sprintf("d.nx != 0: " + string(rune(d.nx))))
	}

	var digest [Size]byte

	binary.BigEndian.PutUint32(digest[0:], d.h[0])
	binary.BigEndian.PutUint32(digest[4:], d.h[1])
	binary.BigEndian.PutUint32(digest[8:], d.h[2])
	binary.BigEndian.PutUint32(digest[12:], d.h[3])
	binary.BigEndian.PutUint32(digest[16:], d.h[4])
	binary.BigEndian.PutUint32(digest[20:], d.h[5])
	binary.BigEndian.PutUint32(digest[24:], d.h[6])
	binary.BigEndian.PutUint32(digest[28:], d.h[7])

	return fmt.Sprintf("%x", digest)
}

func (d *digest) write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func block(dig *digest, p []byte) {
	var w [64]uint32
	h0 := dig.h[0]
	h1 := dig.h[1]
	h2 := dig.h[2]
	h3 := dig.h[3]
	h4 := dig.h[4]
	h5 := dig.h[5]
	h6 := dig.h[6]
	h7 := dig.h[7]

	for len(p) >= chunk {
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}
		for i := 16; i < 64; i++ {
			v1 := w[i-2]
			t1 := (bits.RotateLeft32(v1, -17)) ^ (bits.RotateLeft32(v1, -19)) ^ (v1 >> 10)
			v2 := w[i-15]
			t2 := (bits.RotateLeft32(v2, -7)) ^ (bits.RotateLeft32(v2, -18)) ^ (v2 >> 3)
			w[i] = t1 + w[i-7] + t2 + w[i-16]
		}

		a := h0
		b := h1
		c := h2
		d := h3
		e := h4
		f := h5
		g := h6
		h := h7

		for i := 0; i < 64; i++ {
			t1 := h + ((bits.RotateLeft32(e, -6)) ^ (bits.RotateLeft32(e, -11)) ^ (bits.RotateLeft32(e, -25))) + ((e & f) ^ (^e & g)) + k[i] + w[i]

			t2 := ((bits.RotateLeft32(a, -2)) ^ (bits.RotateLeft32(a, -13)) ^ (bits.RotateLeft32(a, -22))) + ((a & b) ^ (a & c) ^ (b & c))

			h = g
			g = f
			f = e
			e = d + t1
			d = c
			c = b
			b = a
			a = t1 + t2
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
		h5 += f
		h6 += g
		h7 += h

		p = p[chunk:]
	}

	dig.h[0] = h0
	dig.h[1] = h1
	dig.h[2] = h2
	dig.h[3] = h3
	dig.h[4] = h4
	dig.h[5] = h5
	dig.h[6] = h6
	dig.h[7] = h7
}

func goHash(input []byte) string {
	// use a sha256 hash function
	hashgo := sha256.New()

	// write input to hash
	hashgo.Write(input)

	// return hash as string
	return fmt.Sprintf("%x", hashgo.Sum(nil))
}

func main() {
	// print to console
	println("SOP Hasher")
	println("==========")
	println("Skriv en bedsked, som skal hashes:")

	// read input from console
	var input string
	_, err := fmt.Scanln(&input)
	if err != nil {
		return
	}

	// trim input
	input = strings.TrimSpace(input)

	// print input to console
	println("Du skrev: " + input)

	bytes := []byte(input)

	// print Go's hash to console
	print("Go's Hash: " + goHash(bytes))

	// print to console
	print("Good Hash: " + New(bytes))
}
