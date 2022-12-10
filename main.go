package main

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"
)

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

	// print hash to console
	println("Min Hash: " + hash(input))

	// print Go's hash to console
	print("Go's Hash: " + goHash(input))
}

func goHash(input string) string {
	// use a sha256 hash function
	hashgo := sha256.New()

	// write input to hash
	hashgo.Write([]byte(input))

	// return hash as string
	return fmt.Sprintf("%x", hashgo.Sum(nil))
}

func hash(input string) string {
	inputBytes := []byte(input)

	//Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 232
	//Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
	//Note 3: The compression function uses 8 working variables, a through h
	//Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
	//	and when parsing message block data from bytes to words, for example,
	//the first word of the input message "abc" after padding is 0x61626380

	// Initialize hash values:
	//(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
	var h0 uint32 = 0x6A09E667
	var h1 uint32 = 0xBB67AE85
	var h2 uint32 = 0x3C6EF372
	var h3 uint32 = 0xA54FF53A
	var h4 uint32 = 0x510E527F
	var h5 uint32 = 0x9B05688C
	var h6 uint32 = 0x1F83D9AB
	var h7 uint32 = 0x5BE0CD19

	// initialize hash values for 224 bit hash
	var h0_224 uint32 = 0xC1059ED8
	var h1_224 uint32 = 0x367CD507
	var h2_224 uint32 = 0x3070DD17
	var h3_224 uint32 = 0xF70E5939
	var h4_224 uint32 = 0xFFC00B31
	var h5_224 uint32 = 0x68581511
	var h6_224 uint32 = 0x64F98FA7
	var h7_224 uint32 = 0xBEFA4FA4

	// Initialize array of round constants:
	//(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
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

	// Pre-processing:
	// begin with the original message of length L bits
	var L = uint32(len(input))

	// append a single '1' byte
	inputBytes = append(inputBytes, 0x80)

	// append '0' k bits, where k is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
	var kBits uint32 = 0
	for (L+1+kBits+64)%512 != 0 {
		kBits++
	}
	for i := uint32(0); i < kBits; i++ {
		inputBytes = append(inputBytes, 0x00)
	}

	// append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
	var L64 = uint64(L) * 8
	inputBytes = append(inputBytes, byte(L64>>56))
	inputBytes = append(inputBytes, byte(L64>>48))
	inputBytes = append(inputBytes, byte(L64>>40))
	inputBytes = append(inputBytes, byte(L64>>32))
	inputBytes = append(inputBytes, byte(L64>>24))
	inputBytes = append(inputBytes, byte(L64>>16))
	inputBytes = append(inputBytes, byte(L64>>8))
	inputBytes = append(inputBytes, byte(L64))

	// Process the message in successive 512-bit chunks:
	// break message into 512-bit chunks

	// calculate the number of chunks that need to be created
	numChunks := int(math.Ceil(float64(len(inputBytes)) / 64.0))

	// initialize the array to store the chunks
	chunks := make([][]byte, numChunks)

	// chunk the input
	for i := 0; i < len(inputBytes); i += 64 {
		chunks[i/64] = inputBytes[i : i+64]
	}

	// for each chunk
	for _, chunk := range chunks {
		// create a 64-entry message schedule array w[0..63] of 32-bit words
		// (The initial values in w[0..63] don't matter, so many implementations zero them here)
		var w = [64]uint32{}

		// copy chunk into first 16 words w[0..15] of the message schedule array
		for i := 0; i < 16; i++ {
			w[i] = uint32(chunk[i*4])<<24 | uint32(chunk[i*4+1])<<16 | uint32(chunk[i*4+2])<<8 | uint32(chunk[i*4+3])
		}

		// Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
		// for i from 16 to 63
		for i := 16; i < 64; i++ {
			// s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
			var s0 = (w[i-15]>>7 | w[i-15]<<25) ^ (w[i-15]>>18 | w[i-15]<<14) ^ (w[i-15] >> 3)
			// s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
			var s1 uint32 = (w[i-2]>>17 | w[i-2]<<15) ^ (w[i-2]>>19 | w[i-2]<<13) ^ (w[i-2] >> 10)
			// w[i] := w[i-16] + s0 + w[i-7] + s1
			w[i] = w[i-16] + s0 + w[i-7] + s1
		}

		// Initialize working variables to current hash value:
		var a = h0
		var b = h1
		var c = h2
		var d = h3
		var e = h4
		var f = h5
		var g = h6
		var h = h7

		// Compression function main loop:
		// for i from 0 to 63
		for i := 0; i < 64; i++ {
			// S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
			var S1 = (e>>6 | e<<26) ^ (e>>11 | e<<21) ^ (e>>25 | e<<7)
			// ch := (e and f) xor ((not e) and g)
			var ch = (e & f) ^ (^e & g)
			// temp1 := h + S1 + ch + k[i] + w[i]
			var temp1 = h + S1 + ch + k[i] + w[i]
			// S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
			var S0 = (a>>2 | a<<30) ^ (a>>13 | a<<19) ^ (a>>22 | a<<10)
			// maj := (a and b) xor (a and c) xor (b and c)
			var maj = (a & b) ^ (a & c) ^ (b & c)
			// temp2 := S0 + maj
			var temp2 = S0 + maj

			h = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2
		}

		// Add the compressed chunk to the current hash value:
		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
		h5 += f
		h6 += g
		h7 += h
	}

	// Produce the final hash value (big-endian):
	// digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
	var digest []byte
	vars := []uint32{h0, h1, h2, h3, h4, h5, h6, h7}
	for _, v := range vars {
		// extract the first four bytes of the variable and store them in the digest slice
		digest = append(digest, byte(v>>24))
		digest = append(digest, byte(v>>16))
		digest = append(digest, byte(v>>8))
		digest = append(digest, byte(v))
	}

	// return the digest in hex format without using the hex package
	return fmt.Sprintf("%x", digest)

	//return string(digest)
}
