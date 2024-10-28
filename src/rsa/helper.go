// Simple, thoroughly commented implementation of 1024-bit RSA using Google Go aka Golang
// Chris Hulbert - chris.hulbert@gmail.com - http://splinter.com.au/blog
// http://github.com/chrishulbert/crypto
// References:
//  http://www.di-mgt.com.au/rsa_alg.html
//  http://islab.oregonstate.edu/koc/ece575/02Project/Mor/
//  http://people.csail.mit.edu/rivest/Rsapaper.pdf

package rsa

import (
	"math/big"  // For the big numbers required for RSA
	"math/rand" // So we can create random numbers (non-crypto-secure, however)
)

// For the nanoseconds to use for seeding the randomiser

// Make a random bignum of size bits, with the highest two and low bit set
func create_random_bignum(bits int) (num *big.Int) {
	num = big.NewInt(3)         // Start with 3 so the highest 2 bits are set
	one := big.NewInt(1)        // Constant of one
	for num.BitLen() < bits-1 { // Add bits until we're 1 less than we need to be
		num.Lsh(num, 1)        // num <<= 1 (increase the bitsize by 1)
		if rand.Int()&1 == 1 { // set the lowest bit randomly
			num.Add(num, one) // num += 1
		}
	}
	num.Lsh(num, 1)             // num <<= 1 (increase the bitsize by 1)
	num.Add(num, big.NewInt(1)) // num++ - so the lowest bit is set
	return
}

// Create random numbers until it finds a prime
func create_random_prime(bits int) (prime *big.Int) {
	for {
		prime = create_random_bignum(bits) // Create a random number
		if prime.ProbablyPrime(20) {       // Do 20 rabin-miller tests to check if it's prime
			return
		}
	}
	return // This is just here to keep the compiler happy
}
