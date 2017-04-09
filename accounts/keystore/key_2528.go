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

package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lab2528/go-oneTime/accounts"
	"github.com/lab2528/go-oneTime/common"
	"github.com/lab2528/go-oneTime/crypto"
	"github.com/pborman/uuid"
)

const (
	version = 3
)

type Key struct {
	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// to simplify lookups we also store the address
	Address common.Address
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey *ecdsa.PrivateKey

	//////////////////////////////////////////////////////////
	//2528 pengbo add privateKey2 viewKey (a,b)=(PrivateKey,PrivateKey2) //
	//////////////////////////////////////////////////////////
	PrivateKey2 *ecdsa.PrivateKey
	//viewKey     *ecdsa.PrivateKey
}

////////////////////////
// 2528 add onetimekey//
////////////////////////
type OneTimeKey struct {
	//公钥分量，可以含私钥
	OneTimePubAndPri *ecdsa.PrivateKey
	//随机分量
	OneTimeR *ecdsa.PublicKey
}

type keyStore interface {
	// Loads and decrypts the key from disk.
	GetKey(addr common.Address, filename string, auth string) (*Key, error)
	// Writes and encrypts the key.
	StoreKey(filename string, k *Key, auth string) error
	// Joins filename with the key directory unless it is already absolute.
	JoinPath(filename string) string
}

type plainKeyJSON struct {
	Address     string `json:"address"`
	PrivateKey  string `json:"privatekey"`
	PrivateKey2 string `json:"privatekey2"`
	Id          string `json:"id"`
	Version     int    `json:"version"`
}

type encryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version int        `json:"version"`
}

type encryptedKeyJSONV1 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version string     `json:"version"`
}

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

type scryptParamsJSON struct {
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DkLen int    `json:"dklen"`
	Salt  string `json:"salt"`
}

func (k *Key) MarshalJSON() (j []byte, err error) {
	jStruct := plainKeyJSON{
		hex.EncodeToString(k.Address[:]),
		hex.EncodeToString(crypto.FromECDSA(k.PrivateKey)),
		hex.EncodeToString(crypto.FromECDSA(k.PrivateKey2)),
		k.Id.String(),
		version,
	}
	j, err = json.Marshal(jStruct)
	return j, err
}

func (k *Key) UnmarshalJSON(j []byte) (err error) {
	keyJSON := new(plainKeyJSON)
	err = json.Unmarshal(j, &keyJSON)
	if err != nil {
		return err
	}

	u := new(uuid.UUID)
	*u = uuid.Parse(keyJSON.Id)
	k.Id = *u
	addr, err := hex.DecodeString(keyJSON.Address)
	if err != nil {
		return err
	}

	privkey, err := hex.DecodeString(keyJSON.PrivateKey)
	if err != nil {
		return err
	}
	privkey2, err := hex.DecodeString(keyJSON.PrivateKey2)
	if err != nil {
		return err
	}
	k.Address = common.BytesToAddress(addr)
	k.PrivateKey = crypto.ToECDSA(privkey)
	k.PrivateKey2 = crypto.ToECDSA(privkey2)

	return nil
}

//////////////////////////
// add privateKeyECDSA2,viewKey //
//////////////////////////
func GetViewKey(privateKeyECDSA *ecdsa.PrivateKey, privateKeyECDSA2 *ecdsa.PrivateKey) *ecdsa.PrivateKey {
	vKey := new(ecdsa.PrivateKey)
	vKey.D = privateKeyECDSA.D
	vKey.PublicKey = privateKeyECDSA2.PublicKey
	return vKey
}
func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey, privateKeyECDSA2 *ecdsa.PrivateKey) *Key {
	id := uuid.NewRandom()
	// vKey := new(ecdsa.PrivateKey)
	// vKey.D = privateKeyECDSA.D
	// vKey.PublicKey = privateKeyECDSA2.PublicKey
	key := &Key{
		Id:          id,
		Address:     crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey:  privateKeyECDSA,
		PrivateKey2: privateKeyECDSA2,
		//viewKey:     GenViewKey(privateKeyECDSA, privateKeyECDSA2),
		//viewKey: vKey,
	}
	return key
}

// NewKeyForDirectICAP generates a key whose address fits into < 155 bits so it can fit
// into the Direct ICAP spec. for simplicity and easier compatibility with other libs, we
// retry until the first byte is 0.
func NewKeyForDirectICAP(rand io.Reader) *Key {
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic("key generation: could not read from random source: " + err.Error())
	}
	reader := bytes.NewReader(randBytes)
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), reader)
	if err != nil {
		panic("key generation: ecdsa.GenerateKey failed: " + err.Error())
	}
	//////////////////////////////
	// 2528 add privateKeyECDSA2//
	//////////////////////////////
	randBytes2 := make([]byte, 64)
	_, err2 := rand.Read(randBytes2)
	if err2 != nil {
		panic("key generation: could not read from random source2: " + err.Error())
	}
	reader2 := bytes.NewReader(randBytes2)
	privateKeyECDSA2, err2 := ecdsa.GenerateKey(crypto.S256(), reader2)
	if err2 != nil {
		panic("key generation: ecdsa.GenerateKey failed2: " + err.Error())
	}

	key := newKeyFromECDSA(privateKeyECDSA, privateKeyECDSA2)
	if !strings.HasPrefix(key.Address.Hex(), "0x00") {
		return NewKeyForDirectICAP(rand)
	}
	return key
}

////////////////////////////////////
//2528 add rand2 and privateKeyECDSA2 //
////////////////////////////////////
func newKey(rand io.Reader, rand2 io.Reader) (*Key, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)
	//////////////////////////
	//2528 add privateKeyECDSA2 //
	//////////////////////////
	privateKeyECDSA2, err2 := ecdsa.GenerateKey(crypto.S256(), rand2)
	if err != nil {
		return nil, err
	}
	if err2 != nil {
		return nil, err
	}
	return newKeyFromECDSA(privateKeyECDSA, privateKeyECDSA2), nil
}

////////////////////////////////////
//2528 add rand2 //
////////////////////////////////////
func storeNewKey(ks keyStore, rand io.Reader, rand2 io.Reader, auth string) (*Key, accounts.Account, error) {
	key, err := newKey(rand, rand2)
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{Address: key.Address, URL: accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))}}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		zeroKey(key.PrivateKey)
		zeroKey(key.PrivateKey2)
		return nil, a, err
	}
	return key, a, err
}

func writeKeyFile(file string, content []byte) error {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	f.Close()
	return os.Rename(f.Name(), file)
}

// keyFileName implements the naming convention for keyfiles:
// UTC--<created_at UTC ISO8601>-<address hex>
func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}

////////////////////////////////
// 2528 add GenerateOneTimeKey//
////////////////////////////////
func GenerateOneTimeKey(key *Key) (Okey *OneTimeKey, err error) {
	Okey = new(OneTimeKey)
	Okey.OneTimePubAndPri, Okey.OneTimeR, err = crypto.GenerateOneTimeKey(key.PrivateKey, key.PrivateKey2)
	if err != nil {
		return nil, errors.New("GenerateOneTimeKey error")
	}
	return Okey, err
}

////////////////////////////////
// 2528 add CheckOneTimeKey   //
////////////////////////////////
func CheckOneTimeKey(key *Key, Okey *OneTimeKey) bool {
	return crypto.CheckOneTimeKey(key.PrivateKey, key.PrivateKey2, Okey.OneTimePubAndPri, Okey.OneTimeR)
}

////////////////////////////////////////
// 2528 add GenerateOneTimePrivateKey 私钥存放在 Okey.OneTimePubAndPri.D //
////////////////////////////////////////
func GenerateOneTimePrivateKey(key *Key, Okey *OneTimeKey) {
	pub := new(ecdsa.PublicKey)
	pub.X, pub.Y = crypto.S256().ScalarMult(Okey.OneTimeR.X, Okey.OneTimeR.Y, key.PrivateKey.D.Bytes()) //[a]R
	k := new(big.Int).SetBytes(crypto.Keccak256(crypto.FromECDSAPub(pub)))                              //hash([a]R)
	k.Add(k, key.PrivateKey2.D)                                                                         //hash([a]R)+b
	k.Mod(k, crypto.S256().Params().N)                                                                  //mod to feild N
	Okey.OneTimePubAndPri.D = k
}

//////////////////////////////
// 2528 add CheckOneTimePrivateKey //
//////////////////////////////
func CheckOneTimePrivateKey(Okey *OneTimeKey) bool {
	ret := false
	pub := new(ecdsa.PublicKey)
	pub.X, pub.Y = crypto.S256().ScalarBaseMult(Okey.OneTimePubAndPri.D.Bytes()) //[x]G
	if (pub.X.Cmp(Okey.OneTimePubAndPri.PublicKey.X) == 0) && (pub.Y.Cmp(Okey.OneTimePubAndPri.PublicKey.Y) == 0) {
		ret = true
	}
	return ret
}
