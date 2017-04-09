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
	Rand "crypto/rand"
	"io"
	"math/big"
	"math/rand"

	"fmt"

	"github.com/lab2528/go-oneTime/crypto/sha3"
)

var one = new(big.Int).SetInt64(1)

var zero = new(big.Int).SetInt64(0)

func randFieldElement(rand io.Reader) (k *big.Int, err error) {
	params := S256().Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)

	return
}

///calc [x]Hash(P)
func xScalarHashP(x []byte, pub *ecdsa.PublicKey) (I *ecdsa.PublicKey) {
	KeyImg := new(ecdsa.PublicKey)
	I = new(ecdsa.PublicKey)
	KeyImg.X, KeyImg.Y = S256().ScalarBaseMult(Keccak256(FromECDSAPub(pub))) //Hash(P)
	I.X, I.Y = S256().ScalarMult(KeyImg.X, KeyImg.Y, x)
	return
}

//明文，私钥x，公钥组，(P的公钥放在第0位,0....n)  环签名
func RingSign(M []byte, x *big.Int, PublicKeys []*ecdsa.PublicKey) ([]*ecdsa.PublicKey, *ecdsa.PublicKey, []*big.Int, []*big.Int) {
	n := len(PublicKeys)
	fmt.Println(n)
	I := xScalarHashP(x.Bytes(), PublicKeys[0]) //Key Image
	s := rand.Intn(n)                           //s位放主签名公钥
	if s > 0 {
		//s = s - 1
		PublicKeys[0], PublicKeys[s] = PublicKeys[s], PublicKeys[0] //交换位置
	}
	fmt.Println("s=", s)

	//PublicKeys[n] = &P.PublicKey//P的公钥放在第n位,0....n

	var (
		q = make([]*big.Int, n)
		w = make([]*big.Int, n)
	)
	SumC := new(big.Int).SetInt64(0)
	Lpub := new(ecdsa.PublicKey)
	d := sha3.NewKeccak256()
	d.Write(M)
	//hash(M,Li,Ri)
	for i := 0; i < n; i++ {
		q[i], _ = randFieldElement(Rand.Reader)
		w[i], _ = randFieldElement(Rand.Reader)

		Lpub.X, Lpub.Y = S256().ScalarBaseMult(q[i].Bytes()) //[qi]G
		if i != s {
			Ppub := new(ecdsa.PublicKey)
			Ppub.X, Ppub.Y = S256().ScalarMult(PublicKeys[i].X, PublicKeys[i].Y, w[i].Bytes()) //[wi]Pi
			Lpub.X, Lpub.Y = S256().Add(Lpub.X, Lpub.Y, Ppub.X, Ppub.Y)                        //[qi]G+[wi]Pi

			SumC.Add(SumC, w[i])
			SumC.Mod(SumC, secp256k1_N)
		}
		//fmt.Printf("L%d\t%x\n", i, FromECDSAPub(Lpub))
		d.Write(FromECDSAPub(Lpub))
	}
	Rpub := new(ecdsa.PublicKey)
	for i := 0; i < n; i++ {
		Rpub = xScalarHashP(q[i].Bytes(), PublicKeys[i]) //[qi]HashPi
		if i != s {
			Ppub := new(ecdsa.PublicKey)
			Ppub.X, Ppub.Y = S256().ScalarMult(I.X, I.Y, w[i].Bytes())  //[wi]I
			Rpub.X, Rpub.Y = S256().Add(Rpub.X, Rpub.Y, Ppub.X, Ppub.Y) //[qi]HashPi+[wi]I
		}
		//fmt.Printf("R%d\t%x\n", i, FromECDSAPub(Rpub))

		d.Write(FromECDSAPub(Rpub))
	}
	Cs := new(big.Int).SetBytes(d.Sum(nil)) //hash(m,Li,Ri)

	Cs.Sub(Cs, SumC)
	Cs.Mod(Cs, secp256k1_N)

	tmp := new(big.Int).Mul(Cs, x)
	Rs := new(big.Int).Sub(q[s], tmp)
	Rs.Mod(Rs, secp256k1_N)
	w[s] = Cs
	q[s] = Rs

	return PublicKeys, I, w, q
}

//VerifyRingSign 验证环签名
func VerifyRingSign(M []byte, PublicKeys []*ecdsa.PublicKey, I *ecdsa.PublicKey, c []*big.Int, r []*big.Int) bool {
	ret := false
	n := len(PublicKeys)
	SumC := new(big.Int).SetInt64(0)
	Lpub := new(ecdsa.PublicKey)
	d := sha3.NewKeccak256()
	d.Write(M)
	//hash(M,Li,Ri)
	for i := 0; i < n; i++ {
		Lpub.X, Lpub.Y = S256().ScalarBaseMult(r[i].Bytes()) //[ri]G

		Ppub := new(ecdsa.PublicKey)
		Ppub.X, Ppub.Y = S256().ScalarMult(PublicKeys[i].X, PublicKeys[i].Y, c[i].Bytes()) //[ci]Pi
		Lpub.X, Lpub.Y = S256().Add(Lpub.X, Lpub.Y, Ppub.X, Ppub.Y)                        //[ri]G+[ci]Pi
		SumC.Add(SumC, c[i])
		SumC.Mod(SumC, secp256k1_N)
		d.Write(FromECDSAPub(Lpub))
		//fmt.Printf("L'%d\t%x\n", i, FromECDSAPub(Lpub))
	}
	Rpub := new(ecdsa.PublicKey)
	for i := 0; i < n; i++ {
		Rpub = xScalarHashP(r[i].Bytes(), PublicKeys[i]) //[qi]HashPi
		Ppub := new(ecdsa.PublicKey)
		Ppub.X, Ppub.Y = S256().ScalarMult(I.X, I.Y, c[i].Bytes())  //[wi]I
		Rpub.X, Rpub.Y = S256().Add(Rpub.X, Rpub.Y, Ppub.X, Ppub.Y) //[qi]HashPi+[wi]I
		//fmt.Printf("R'%d\t%x\n", i, FromECDSAPub(Rpub))

		d.Write(FromECDSAPub(Rpub))
	}
	hash := new(big.Int).SetBytes(d.Sum(nil)) //hash(m,Li,Ri)
	hash.Mod(hash, secp256k1_N)

	if hash.Cmp(SumC) == 0 {
		ret = true
	}
	return ret
}
