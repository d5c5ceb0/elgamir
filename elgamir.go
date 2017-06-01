package elgamir

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	mrand "math/rand"
	"time"
)

var (
	ReserveIdx = 1
	UserIdx    = 100
)

type KeyShare struct {
	privKeyShare
	PubKeyShare
}

type privKeyShare struct {
	X, Y *big.Int
}

type PubKeyShare struct {
	X, Y *big.Int
}

type ElCipher struct {
	C1 *big.Int
	C2 *big.Int
	C3 []PubKeyShare
}

type ElgamalPara struct {
	ElgamalP *big.Int
	ElgamalG *big.Int
	ElgamalQ *big.Int
	ParamLen int
}

func Setup(ParamLen int) (ElgamalPara, error) {
	para := ElgamalPara{}
	for {
		para.ElgamalP, _ = rand.Prime(rand.Reader, ParamLen*8)
		para.ElgamalQ = new(big.Int).Sub(para.ElgamalP, big.NewInt(1))
		para.ElgamalQ = new(big.Int).Div(para.ElgamalQ, big.NewInt(2))
		ok := para.ElgamalQ.ProbablyPrime(50)
		if ok == true {
			break
		}
	}

	for {
		k := make([]byte, ParamLen/2)
		_, err := io.ReadFull(rand.Reader, k)
		if err != nil {
			return ElgamalPara{}, errors.New("RandFull error.")
		}
		para.ElgamalG = new(big.Int).SetBytes(k)
		para.ElgamalG = new(big.Int).Mul(para.ElgamalG, para.ElgamalG)
		if para.ElgamalG.Cmp(big.NewInt(4)) == -1 {
			continue
		}
		if para.ElgamalG.Cmp(para.ElgamalQ) == -1 {
			break
		}
	}

	para.ParamLen = ParamLen

	return para, nil
}

func (para *ElgamalPara) interpolate(shareX *big.Int, shares []PubKeyShare) PubKeyShare {
	shareY := big.NewInt(1)
	for _, sharei := range shares {
		xa := sharei.X
		ya := sharei.Y
		weight := big.NewInt(1)
		for _, sharej := range shares {
			xb := sharej.X

			if xa.Cmp(xb) != 0 {
				top := new(big.Int).Sub(shareX, xb)
				bottom := new(big.Int).Sub(xa, xb)
				bottom = new(big.Int).Mod(bottom, para.ElgamalQ)
				inv := new(big.Int).ModInverse(bottom, para.ElgamalQ)
				factor := new(big.Int).Mul(top, inv)
				weight = new(big.Int).Mul(weight, factor)
				weight = new(big.Int).Mod(weight, para.ElgamalQ)
			}
		}
		temp := new(big.Int).Exp(ya, weight, para.ElgamalP)
		shareY = new(big.Int).Mul(shareY, temp)
		shareY = new(big.Int).Mod(shareY, para.ElgamalP)
	}

	return PubKeyShare{X: shareX, Y: shareY}
}

func (para *ElgamalPara) ShareKeyGen(shareX *big.Int) KeyShare {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	share := new(big.Int).Rand(r, para.ElgamalQ)
	gshare := new(big.Int).Exp(para.ElgamalG, share, para.ElgamalP)

	return KeyShare{privKeyShare{X: shareX, Y: share}, PubKeyShare{X: shareX, Y: gshare}}
}

func (para *ElgamalPara) getPubkey(shares []PubKeyShare) (*big.Int, []PubKeyShare, error) {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	secret := new(big.Int).Rand(r, para.ElgamalQ)
	shareLen := len(shares)

	share0X := big.NewInt(0)
	share0Y := new(big.Int).Exp(para.ElgamalG, secret, para.ElgamalP)
	shares = append(shares, PubKeyShare{X: share0X, Y: share0Y})

	newShares := make([]PubKeyShare, 0)
	for i := 0; i < shareLen; i++ {
		newShares = append(newShares, para.interpolate(big.NewInt(int64(ReserveIdx+i)), shares))
	}

	recovershares := append(newShares, shares[0])
	recover := para.interpolate(big.NewInt(0x00), recovershares)
	if recover.Y.Cmp(share0Y) != 0 {
		return nil, []PubKeyShare{}, errors.New("getPubkey: recover secret failed.")
	}

	return share0Y, newShares[:], nil
}

func (para *ElgamalPara) getPrivkey(privShare privKeyShare, c ElCipher) *big.Int {
	y := new(big.Int).Exp(c.C1, privShare.Y, para.ElgamalP)
	c.C3 = append(c.C3, PubKeyShare{X: privShare.X, Y: y})
	secret := para.interpolate(big.NewInt(0x00), c.C3)

	return secret.Y
}

func (para *ElgamalPara) Encrypt(shares []PubKeyShare, msg []byte) (ElCipher, error) {
	pubkey, newShares, err := para.getPubkey(shares)
	if err != nil {
		return ElCipher{}, errors.New("genPubkey error")
	}
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	y := new(big.Int).Rand(r, para.ElgamalQ)

	c := ElCipher{}
	c.C1 = new(big.Int).Exp(para.ElgamalG, y, para.ElgamalP)
	s := new(big.Int).Exp(pubkey, y, para.ElgamalP)
	c.C2 = new(big.Int).Mul(s, new(big.Int).SetBytes(msg))
	c.C2 = new(big.Int).Mod(c.C2, para.ElgamalP)
	c.C3 = make([]PubKeyShare, 0)
	for _, share := range newShares {
		cshare := new(big.Int).Exp(share.Y, y, para.ElgamalP)
		c.C3 = append(c.C3, PubKeyShare{X: share.X, Y: cshare})
	}

	return c, nil
}

func (para *ElgamalPara) Decrypt(privShare privKeyShare, c ElCipher) []byte {
	s := para.getPrivkey(privShare, c)
	sinv := new(big.Int).ModInverse(s, para.ElgamalP)
	msg := new(big.Int).Mul(c.C2, sinv)
	msg = new(big.Int).Mod(msg, para.ElgamalP)

	return msg.Bytes()
}
