package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/term"
)

type Auth0Response struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

type GetPartialRecoveryResponse struct {
	Success bool   `json:"success"`
	Data    string `json:"data"`
}

type RecoveryMethod string

const (
	LOCAL_PRIVATE_KEY  RecoveryMethod = "1"
	HSM_TOKEN          RecoveryMethod = "2"
	MOBILE_PRIVATE_KEY RecoveryMethod = "3"
)

type RecoveryType string

const (
	MOBILE RecoveryType = "1"
	SERVER RecoveryType = "2"
)

const (
	ECDSA     string = "ecdsa"
	SECP256K1 string = "secp256k1"

	EDDSA   string = "eddsa"
	ED25519 string = "ed25519"
)

const apiUrl = "https://api.lmnl.app"
const auth0Url = "https://lmnlhq.us.auth0.com/oauth/token"
const auth0Audience = "https://api.lmnl.app/api/"

func mustParseURL(urlStr string) url.URL {
	u, err := url.Parse(urlStr)
	if err != nil {
		panic(err)
	}
	return *u
}

func registerTenant(publicKey string, walletId int64, token string, sessionId string) error {
	postBody, _ := json.Marshal(map[string]string{
		"publicKey": publicKey,
		"sessionId": sessionId,
		"walletId":  strconv.FormatInt(walletId, 10),
		"version":   "52",
	})

	req, err := http.NewRequest("POST", apiUrl+"/api/wallet/"+strconv.FormatInt(walletId, 10)+"/registerTenantPublicKey", bytes.NewBuffer(postBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Add("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	return nil
}

func startLiminalRecoveryInfo(keyId string, token string, pubKey []byte, sessionId string) (*string, error) {
	ersPubKey := base64.StdEncoding.EncodeToString(pubKey)

	postBody, _ := json.Marshal(map[string]string{
		"sessionId": sessionId,
		"publicKey": ersPubKey,
		"keyId":     keyId,
		"version":   strconv.FormatInt(52, 10),
	})

	req, err := http.NewRequest("POST", apiUrl+"/api/account/generatePartialRecoveryInfo", bytes.NewBuffer(postBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("authorization", "Bearer "+token)
	req.Header.Add("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var getPartialRecoveryResp GetPartialRecoveryResponse
	err = json.Unmarshal(body, &getPartialRecoveryResp)
	if err != nil {
		return nil, err
	}
	if !getPartialRecoveryResp.Success {
		return nil, errors.New("error generating recovery info")
	}
	return &getPartialRecoveryResp.Data, nil
}

func getAuth0Token(clientId string, clientSecret string) (*string, error) {
	postBody, _ := json.Marshal(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientId,
		"client_secret": clientSecret,
		"audience":      auth0Audience,
	})
	req, err := http.NewRequest("POST", auth0Url, bytes.NewBuffer(postBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var auth0Response Auth0Response
	err = json.Unmarshal(body, &auth0Response)
	if err != nil {
		return nil, err
	}
	if auth0Response.Error != "" {
		return nil, errors.New(auth0Response.Error)
	}
	return &auth0Response.AccessToken, nil
}

func getAccountDetails(token string) (*string, *string, error) {
	req, err := http.NewRequest("GET", apiUrl+"/api/account/me", nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("authorization", "Bearer "+token)
	req.Header.Add("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, nil, err
	}
	var meResp map[string]interface{}
	err = json.Unmarshal(body, &meResp)
	if err != nil {
		return nil, nil, err
	}
	var ecdsaKeyId string
	var eddsaKeyId string
	keys, ok := meResp["keys"]
	if ok {
		for _, data := range keys.(map[string]interface{}) {
			for _, val := range data.([]interface{}) {
				algorithm, ok := val.(map[string]interface{})["algorithm"]
				defaultKeyId, ok2 := val.(map[string]interface{})["defaultKeyId"]
				provider, ok3 := val.(map[string]interface{})["provider"]
				version, ok4 := val.(map[string]interface{})["nodeversion"]
				if ok && ok2 && ok3 && ok4 && provider == "MPC" && defaultKeyId != nil && version == "52" {
					if algorithm == nil || strings.ToLower(algorithm.(string)) == "ecdsa" || strings.ToLower(algorithm.(string)) == "" {
						ecdsaKeyId = val.(map[string]interface{})["defaultKeyId"].(string)
					}
					if algorithm != nil && strings.ToLower(algorithm.(string)) == "eddsa" {
						eddsaKeyId = val.(map[string]interface{})["defaultKeyId"].(string)
					}
				}

				if ecdsaKeyId != "" && eddsaKeyId != "" {
					break
				}
			}
		}
	}
	return &ecdsaKeyId, &eddsaKeyId, nil
}

var xprv = []byte{0x04, 0x88, 0xAD, 0xE4}
var xpub = []byte{0x04, 0x88, 0xB2, 0x1E}
var tprv = []byte{0x04, 0x35, 0x83, 0x94}
var tpub = []byte{0x04, 0x35, 0x87, 0xCF}

func encodeKey(public, production bool, payload []byte, chainCode []byte) (string, error) {
	w := bytes.Buffer{}
	switch {
	case production && public:
		_, _ = w.Write(xpub)
	case !production && public:
		_, _ = w.Write(tpub)
	case production && !public:
		_, _ = w.Write(xprv)
	case !production && !public:
		_, _ = w.Write(tprv)
	}
	_ = w.WriteByte(byte(0))
	_, _ = w.Write([]byte{0, 0, 0, 0})
	_, _ = w.Write([]byte{0, 0, 0, 0})
	_, _ = w.Write(chainCode)
	if !public {
		_, _ = w.Write([]byte{0x00})
	}
	encoded := payload // ser256(k)
	_, _ = w.Write(encoded)

	return base58WithChecksum(w.Bytes()), nil
}

func base58WithChecksum(input []byte) string {
	b := make([]byte, 0, len(input)+4)
	b = append(b, input[:]...)

	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	b = append(b, h2[:4]...)
	return base58.Encode(b)
}
func newSecp256k1() curve {
	a := new(big.Int).SetInt64(0)
	b := new(big.Int).SetInt64(7)

	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	q, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

	gx, _ := new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gy, _ := new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	return curve{
		name: "secp256k1",
		a:    a,
		b:    b,
		p:    p,
		q:    q,
		gx:   gx,
		gy:   gy,
	}
}

var (
	zero          = new(big.Int).SetInt64(0)
	three         = new(big.Int).SetInt64(3)
	curveFromName = map[string]curve{
		"secp256k1": newSecp256k1(),
	}
)

func (c curve) newPoint(x, y *big.Int) (point, error) {
	if x.BitLen() == 0 && y.BitLen() == 0 {
		return c.o(), nil
	}

	l := new(big.Int).Mul(y, y)
	l.Mod(l, c.p)
	l.Sub(l, c.b)
	l.Mod(l, c.p)

	r := new(big.Int).Mul(x, x)
	r.Mod(r, c.p)
	r.Add(r, c.a)
	r.Mul(r, x)
	r.Mod(r, c.p)

	if l.Cmp(r) != 0 {
		return point{}, fmt.Errorf("invalid coordinates for elliptic curve: %s", c.name)
	}

	return point{
		curve: c,
		x:     x.Mod(x, c.p),
		y:     y.Mod(y, c.p),
	}, nil
}

func (c curve) g() point {
	return point{
		curve: c,
		x:     c.gx,
		y:     c.gy,
	}
}

func (c curve) o() point {
	return point{
		curve: c,
		x:     zero,
		y:     zero,
	}
}

func (c curve) decodeUncompressedPoint(b []byte) (point, error) {
	elementSize := (c.p.BitLen() + 7) / 8
	if len(b) == 1 && b[0] == 0 {
		p, err := c.newPoint(big.NewInt(0), big.NewInt(0))
		if err != nil {
			return point{}, errors.New("invalid 0-point")
		}
		return p, nil
	} else {
		if len(b) != 1+2*elementSize {
			return point{}, errors.New("invalid point length")
		}
		if b[0] != 4 {
			return point{}, errors.New("invalid point type")
		}

		x := new(big.Int).SetBytes(b[1 : elementSize+1])
		y := new(big.Int).SetBytes(b[elementSize+1:])

		p, err := c.newPoint(x, y)
		if err != nil {
			return point{}, errors.New("invalid point values")
		}
		return p, nil
	}
}

func (p point) coordinates() (*big.Int, *big.Int) {
	x := new(big.Int).Set(p.x)
	y := new(big.Int).Set(p.y)
	return x, y
}

func (p point) dbl() point {
	if p.equals(p.curve.o()) {
		return p
	}

	tmp1 := new(big.Int).Mul(p.x, p.x)
	tmp1.Mod(tmp1, p.curve.p)
	tmp1.Mul(tmp1, three)
	tmp1.Add(tmp1, p.curve.a)
	tmp2 := new(big.Int).Add(p.y, p.y)
	tmp2.ModInverse(tmp2, p.curve.p)
	tmp1.Mul(tmp1, tmp2)
	tmp1.Mod(tmp1, p.curve.p)

	x := new(big.Int).Mul(tmp1, tmp1)
	x.Mod(x, p.curve.p)
	tmp2.Add(p.x, p.x)
	x.Sub(x, tmp2)

	y := new(big.Int).Sub(p.x, x)
	y.Mul(y, tmp1)
	y.Mod(y, p.curve.p)
	y.Sub(y, p.y)

	return point{
		curve: p.curve,
		x:     x.Mod(x, p.curve.p),
		y:     y.Mod(y, p.curve.p),
	}
}

func (p point) add(q point) point {
	if p.equals(q) {
		return p.dbl()
	}

	if p.equals(p.curve.o()) {
		return q
	}

	if q.equals(q.curve.o()) {
		return p
	}

	if p.equals(q.neg()) {
		return p.curve.o()
	}

	tmp1 := new(big.Int).Sub(q.y, p.y)
	tmp2 := new(big.Int).Sub(q.x, p.x)
	tmp2.ModInverse(tmp2, p.curve.p)
	tmp1.Mul(tmp1, tmp2)
	tmp1.Mod(tmp1, p.curve.p)

	x := new(big.Int).Mul(tmp1, tmp1)
	x.Mod(x, p.curve.p)
	x.Sub(x, p.x)
	x.Sub(x, q.x)

	y := new(big.Int).Sub(p.x, x)
	y.Mul(y, tmp1)
	y.Mod(y, p.curve.p)
	y.Sub(y, p.y)

	return point{
		curve: p.curve,
		x:     x.Mod(x, p.curve.p),
		y:     y.Mod(y, p.curve.p),
	}
}

func (p point) sub(q point) point {
	return p.add(q.neg())
}

func (p point) neg() point {
	negY := new(big.Int).Neg(p.y)

	return point{
		curve: p.curve,
		x:     p.x,
		y:     negY.Mod(negY, p.curve.p),
	}
}

func (p point) mul(k *big.Int) point {
	k = new(big.Int).Mod(k, p.curve.q)
	r0 := p.curve.o()
	r1 := p

	for i := k.BitLen() - 1; i >= 0; i-- {
		if k.Bit(i) == 0 {
			r1 = r1.add(r0)
			r0 = r0.dbl()
		} else {
			r0 = r0.add(r1)
			r1 = r1.dbl()
		}
	}

	return r0
}

func (p point) equals(q point) bool {
	if p.curve.name != q.curve.name {
		return false
	}

	if p.x.Cmp(q.x) != 0 || p.y.Cmp(q.y) != 0 {
		return false
	}

	return true
}

type curve struct {
	name string
	a    *big.Int
	b    *big.Int
	p    *big.Int
	q    *big.Int
	gx   *big.Int
	gy   *big.Int
}

type point struct {
	curve curve
	x     *big.Int
	y     *big.Int
}

func encodePoint(p point) ([]byte, error) {
	var pBuf = &bytes.Buffer{}
	if p.y.Bit(0) == 0 {
		_ = pBuf.WriteByte(0x02)
	} else {
		_ = pBuf.WriteByte(0x03)
	}
	for i := len(p.x.Bytes()); i < 32; i++ {
		_ = pBuf.WriteByte(0x0)
	}
	_, _ = pBuf.Write(p.x.Bytes())
	return pBuf.Bytes(), nil
}

func parseASN1PublicKey(skBytes []byte) ([]byte, error) {
	//SEQUENCE (3 elem)
	//  INTEGER 1
	//  OCTET STRING (32 byte) E15AECACD7CB3304435D1FCCBA1132449E74FDA2EE2205516D165015E2041E1B
	//  [0] (1 elem)
	//    OBJECT IDENTIFIER 1.3.132.0.10 secp256k1 (SECG (Certicom) named elliptic curve)
	type ASN1Key struct {
		Seq interface{}
		Key asn1.BitString
	}
	var key ASN1Key
	rest, err := asn1.Unmarshal(skBytes, &key)
	if err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("ASN1 struct contains additional data: %v", rest)
	}
	return key.Key.Bytes, nil
}

func TakeInput(text string) string {
	var input string

	fmt.Println(text)
	_, err := fmt.Scanln(&input)
	if err != nil {
		log.Fatal(err)
		return ""
	}

	return input
}

func TakePasswordInput(text string) string {
	fmt.Println(text)
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
		return ""
	}

	return string(bytepw)
}

func SaveFile(name, content string) error {
	file, err := os.Create(name)
	if err != nil {
		return err
	}
	defer file.Close()
	file.WriteString(content)

	return nil
}

func checkError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

func askForConfirmation(prompt string) bool {
	fmt.Println(prompt + " (y/n)")
	var input string
	_, err := fmt.Scanln(&input)
	checkError(err, "Error reading input")
	return strings.ToLower(input) == "y" || strings.ToLower(input) == "yes"
}

func getBIP32Path() []uint32 {
	input := TakeInput("Enter BIP 32 Path (It looks like m/XX/YY/A/B/C)")

	var chainpath []uint32

	bip32Path := strings.Split(input, "/")
	for i, value := range bip32Path {
		if i == 0 && value == "m" {
			continue
		}
		bipIndex, err := strconv.ParseInt(value, 10, 64)
		checkError(err, "Invalid path")
		chainpath = append(chainpath, uint32(bipIndex))
	}
	return chainpath
}
