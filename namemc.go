package apiGO

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Tnze/go-mc/bot"
	"github.com/Tnze/go-mc/bot/basic"
	"github.com/Tnze/go-mc/chat"
	"github.com/Tnze/go-mc/data/packetid"
	pk "github.com/Tnze/go-mc/net/packet"
)

func NameMC(Bearer string) string {
	C := bot.NewClient()
	B := GetProfileInformation(Bearer)
	C.Auth = bot.Auth{
		AsTk: Bearer,
		UUID: B.ID,
		Name: B.Name,
	}
	basic.EventsListener{
		GameStart: func() error {
			go func() {
				time.Sleep(time.Millisecond * 500)
				SendMessage(C, "/namemc")

			}()
			return nil
		},
		SystemMsg: func(c chat.Message, pos byte) error {
			if KEY := c.ClearString(); strings.Contains(KEY, "https://namemc.com/claim?key=") {
				return errors.New("got-key+" + KEY)
			}
			return nil
		},
	}.Attach(C)
	C.JoinServer("blockmania.com")
	if err := C.HandleGame(); err != nil && strings.Contains(err.Error(), "got-key") {
		return strings.Split(err.Error(), "+")[1]
	}
	return "Error: Unable to find a valid url."
}

// https://github.com/bitbanger/go-mc/blob/master/bot/chat.go

func ChatSignatureData(c *bot.Client, msg string, timestamp time.Time) ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(timestamp.Unix()))

	var data []byte
	data = append(data, []byte{0, 0, 0, 0, 0, 0, 0, 0}...)
	data = append(data, c.UUID[:]...)
	data = append(data, b...)

	jsonStr, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	data = append(data, []byte(fmt.Sprintf("{\"text\":\"%s\"}", string(jsonStr[1:len(jsonStr)-1])))...)

	return data, nil
}

func SignChatMessage(c *bot.Client, msg string, timestamp time.Time) ([]byte, error) {
	privateKeyBlock, _ := pem.Decode([]byte(c.KeyPair.KeyPair.PrivateKey))
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	key := privateKey.(*rsa.PrivateKey)
	hash := sha256.New()
	csd, err := ChatSignatureData(c, msg, timestamp)
	if err != nil {
		return nil, err
	}
	hash.Write(csd)
	signedData, err := key.Sign(rand.Reader, hash.Sum(nil), crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return signedData, nil
}

func SendMessage(c *bot.Client, msg string) error {
	timestamp := time.Now()
	signed, err := SignChatMessage(c, msg, timestamp)
	if err != nil {
		return err
	}

	return c.Conn.WritePacket(pk.Marshal(
		packetid.ServerboundChat,
		pk.String(msg),
		pk.Long(timestamp.UnixNano()/1000000),
		pk.Long(0), // no salt
		pk.ByteArray(signed),
		pk.Boolean(false),
	))
}
