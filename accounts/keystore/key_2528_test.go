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

//ts 123
package keystore

import (
	"crypto/rand"
	"fmt"
	"testing"

	"crypto/ecdsa"

	"github.com/lab2528/go-oneTime/crypto"
)

func TestGenerateOneTimeKeyAndCheck(t *testing.T) {
	key, _ := newKey(rand.Reader, rand.Reader)
	fmt.Println("------------newKey------------")
	fmt.Printf("address:\t %x\n", key.Address)
	fmt.Printf("A:\t %x\n", crypto.FromECDSAPub(&key.PrivateKey.PublicKey))
	fmt.Printf("a:\t %x\n", key.PrivateKey.D.Bytes())
	fmt.Printf("B:\t %x\n", crypto.FromECDSAPub(&key.PrivateKey2.PublicKey))
	fmt.Printf("b:\t %x\n", key.PrivateKey2.D.Bytes())
	fmt.Printf("b:\t %x\n", crypto.Keccak256(key.PrivateKey2.D.Bytes(), key.PrivateKey.D.Bytes(), crypto.FromECDSAPub(&key.PrivateKey2.PublicKey)))
	Okey, _ := GenerateOneTimeKey(key)
	ret := false
	ret = CheckOneTimeKey(key, Okey)
	fmt.Println("check OneTimeKey", ret)
	GenerateOneTimePrivateKey(key, Okey)
	ret = CheckOneTimePrivateKey(Okey)
	fmt.Println("check OneTimePrivateKey", ret)
}
func TestRingSignAndVerify(t *testing.T) {
	key1, _ := newKey(rand.Reader, rand.Reader)
	key2, _ := newKey(rand.Reader, rand.Reader)
	msg := []byte("abc")
	var pub = make([]*ecdsa.PublicKey, 0)
	pub = append(pub, &key1.PrivateKey.PublicKey, &key2.PrivateKey.PublicKey)
	//pub[1] = &key2.PrivateKey.PublicKey
	Pub, I, c, r := crypto.RingSign(msg, key1.PrivateKey.D, pub)
	ret := false
	ret = crypto.VerifyRingSign(msg, Pub, I, c, r)
	fmt.Println("check VerifyRingSign", ret)
}
