// Package rawrsa implements "raw" or "textbook" RSA signing and verification.
// Although this normally leads to an insecure signature scheme,
// these primitives are needed to implement blind RSA signatures.
package rawrsa

import (
  "crypto/rsa"
  "math/big"
)

// encrypt performs an RSA encryption, returning the ciphertext.
//
// This function is from crypto/rsa.
func encrypt(pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	return new(big.Int).Exp(m, e, pub.N)
}

// decrypt performs an RSA decryption, storing the plaintext in m.
//
// This function is adapted from crypto/rsa.
func decrypt(priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priv.N) > 0 {
		return nil, rsa.ErrDecryption
	}
	if priv.N.Sign() == 0 {
    return nil, rsa.ErrDecryption
	}

	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)
	}

	return
}

// Sign signs a message with the "textbook RSA" signature scheme.
func Sign(priv *rsa.PrivateKey, msg *big.Int) (*big.Int, error) {
  return decrypt(priv, msg)
}

// Verify verifies that sig is a valid "textbook RSA" signature for msg.
func Verify(pub *rsa.PublicKey, msg *big.Int, sig *big.Int) bool {
  m := encrypt(pub, sig)
  return m.Cmp(msg) == 0
}
