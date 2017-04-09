// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/lab2528/go-oneTime/common"
	"github.com/lab2528/go-oneTime/crypto/sha3"
	"github.com/lab2528/go-oneTime/rlp"
)

var (
	secp256k1_N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1_halfN = new(big.Int).Div(secp256k1_N, big.NewInt(2))
)

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}

// Keccak512 calculates and returns the Keccak512 hash of the input data.
func Keccak512(data ...[]byte) []byte {
	d := sha3.NewKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Deprecated: For backward compatibility as other packages depend on these
func Sha3Hash(data ...[]byte) common.Hash { return Keccak256Hash(data...) }

// Creates an ethereum address given the bytes and the nonce
func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(Keccak256(data)[12:])
}

// ToECDSA creates a private key with the given D value.
func ToECDSA(prv []byte) *ecdsa.PrivateKey {
	if len(prv) == 0 {
		return nil
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = S256()
	priv.D = new(big.Int).SetBytes(prv)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(prv)
	return priv
}

func FromECDSA(prv *ecdsa.PrivateKey) []byte {
	if prv == nil {
		return nil
	}
	return prv.D.Bytes()
}

func ToECDSAPub(pub []byte) *ecdsa.PublicKey {
	if len(pub) == 0 {
		return nil
	}
	x, y := elliptic.Unmarshal(S256(), pub)
	return &ecdsa.PublicKey{Curve: S256(), X: x, Y: y}
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(S256(), pub.X, pub.Y)
}

// HexToECDSA parses a secp256k1 private key.
func HexToECDSA(hexkey string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, errors.New("invalid hex string")
	}
	if len(b) != 32 {
		return nil, errors.New("invalid length, need 256 bits")
	}
	return ToECDSA(b), nil
}

// LoadECDSA loads a secp256k1 private key from the given file.
// The key data is expected to be hex-encoded.
func LoadECDSA(file string) (*ecdsa.PrivateKey, error) {
	buf := make([]byte, 64)
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	if _, err := io.ReadFull(fd, buf); err != nil {
		return nil, err
	}

	key, err := hex.DecodeString(string(buf))
	if err != nil {
		return nil, err
	}

	return ToECDSA(key), nil
}

// SaveECDSA saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(FromECDSA(key))
	return ioutil.WriteFile(file, []byte(k), 0600)
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(S256(), rand.Reader)
}

// ValidateSignatureValues verifies whether the signature values are valid with
// the given chain rules. The v value is assumed to be either 0 or 1.
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	if r.Cmp(common.Big1) < 0 || s.Cmp(common.Big1) < 0 {
		return false
	}
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	if homestead && s.Cmp(secp256k1_halfN) > 0 {
		return false
	}
	// Frontier: allow s to be in full N range
	return r.Cmp(secp256k1_N) < 0 && s.Cmp(secp256k1_N) < 0 && (v == 0 || v == 1)
}

func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(&p)
	return common.BytesToAddress(Keccak256(pubBytes[1:])[12:])
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

////////////////////////////////
// 2528 add A1=[hash([r]A)]G+B//
////////////////////////////////
func generateA1(r []byte, A *ecdsa.PublicKey, B *ecdsa.PublicKey) ecdsa.PublicKey {
	A1 := new(ecdsa.PublicKey)
	A1.X, A1.Y = S256().ScalarMult(A.X, A.Y, r) //A1=[r]A
	//A1Bytes := FromECDSAPub(A1)
	A1Bytes := Keccak256(FromECDSAPub(A1))        //hash([r]A)
	A1.X, A1.Y = S256().ScalarBaseMult(A1Bytes)   //[hash([r]A)]G
	A1.X, A1.Y = S256().Add(A1.X, A1.Y, B.X, B.Y) //A1=[hash([r]A)]G+B
	return *A1
}

////////////////////////////////
// 2528 add GenerateOneTimeKey//
////////////////////////////////
func GenerateOneTimeKey(A *ecdsa.PrivateKey, B *ecdsa.PrivateKey) (A1 *ecdsa.PrivateKey, R *ecdsa.PublicKey, err error) {
	//RPrivateKey=(r,R)
	RPrivateKey, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	R = &RPrivateKey.PublicKey
	A1 = new(ecdsa.PrivateKey)
	A1.PublicKey = generateA1(RPrivateKey.D.Bytes(), &A.PublicKey, &B.PublicKey)
	return A1, R, err
}

//////////////////////////////
// 2528 add CheckOneTimeKey //
//////////////////////////////
func CheckOneTimeKey(A *ecdsa.PrivateKey, B *ecdsa.PrivateKey, A1 *ecdsa.PrivateKey, R *ecdsa.PublicKey) bool {
	ret := false
	A1p := generateA1(A.D.Bytes(), R, &B.PublicKey) //A1p=[hash([a]R)]G+B
	if (A1p.X.Cmp(A1.PublicKey.X) == 0) && (A1p.Y.Cmp(A1.PublicKey.Y) == 0) {
		ret = true
	}
	return ret
}
