package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	addr       string = "x.x.x.x:8080"
	role_id    string = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	secret_id  string = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	vault_addr string = "https://vault.yourdomain.com:8200"
)

var (
	client         *api.Client
	jsonData       []byte
	scrapeInterval string
	listenPort     string
	remootioIP     string

	doorState = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "doorStatus",
		Help: "Current status of the garage door.",
	})
)

type encryptedRequest struct {
	Type string `json:"type"`
	Data data   `json:"data"`
	Mac  string `json:"mac"`
}

type data struct {
	Iv      string `json:"iv"`
	Payload string `json:"payload"`
}

type challengeAuth struct {
	Type      string
	Challenge challenge
}

type challenge struct {
	SessionKey      string
	InitialActionId int
}

type hmacObject struct {
	Iv      string
	Payload string
}

type doorStatus struct {
	Response doorResponse `json:"response"`
}

type doorResponse struct {
	Type           string `json:"type"`
	Id             int    `json:"id"`
	Success        string `json:"success"`
	State          string `json:"state"`
	T100ms         int    `json:"t100ms"`
	RelayTriggered string `json:"relayTriggered"`
	ErrorCode      string `json:"errorCode"`
}

func init() {
	// Register guage with Prometheus
	prometheus.MustRegister(doorState)
}

func main() {
	// Get env vars
	scrapeInterval = os.Getenv("scrapeInterval")
	if len(scrapeInterval) == 0 {
		scrapeInterval = "10"
	}
	scrapeIntervali, _ := strconv.Atoi(scrapeInterval)
	listenPort = ":" + os.Getenv("listenPort")
	if len(listenPort) == 1 {
		listenPort = ":2112"
	}
	remootioIP = os.Getenv("remootioIP")
	if len(remootioIP) == 0 {
		remootioIP = addr
	}

	log.SetFlags(0)

	handler()

	// scrapeInterval * seconds
	ticker := time.NewTicker(time.Duration(scrapeIntervali) * time.Second)

	go func() {
		for {
			select {
			case t := <-ticker.C:
				fmt.Println("Tick at", t)
				handler()
			}
		}
	}()

	// Start Prometheus server
	fmt.Println("Starting prom server on port ", listenPort)
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(listenPort, nil)
}

func handler() {
	fmt.Println("Handler invoked")

	// Connect to Remootio Websocket
	u := url.URL{Scheme: "ws", Host: remootioIP, Path: "/"}
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("Error:", err)
	}
	defer c.Close()

	authKeyHex, err := getSecret("auth_key")
	if err != nil {
		log.Fatal("Error:", err)
	}
	authKey, err := hex.DecodeString(authKeyHex)
	if err != nil {
		log.Fatal("Error:", err)
	}
	secretKeyHex, err := getSecret("secret_key")
	if err != nil {
		log.Fatal("Error:", err)
	}
	secretKey, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		log.Fatal("Error:", err)
	}
	seshKey, initId := authoriseRequest(c, secretKey)
	result := getDoorStatus(c, secretKey, authKey, seshKey, initId)

	switch result {
	case "open":
		doorState.Set(1)
	case "closed":
		doorState.Set(0)
	}
}

func readResponse(c *websocket.Conn) ([]byte, error) {
	_, message, err := c.ReadMessage()
	if err != nil {
		log.Println("Error:", err)
		return nil, err
	}
	return message, nil
}

func pingRequest(c *websocket.Conn) ([]byte, error) {
	err := c.WriteMessage(websocket.TextMessage, []byte("{\"type\":\"PING\"}"))
	if err != nil {
		log.Println("Error:", err)
	}
	data, err := readResponse(c)
	return data, err
}

func authoriseRequest(c *websocket.Conn, secretKey []byte) (string, int) {
	var initOutput encryptedRequest

	err := c.WriteMessage(websocket.TextMessage, []byte("{\"type\":\"AUTH\"}"))
	if err != nil {
		log.Println("Error:", err)
	}
	data, err := readResponse(c)
	if err != nil {
		log.Println("Error:", err)
	}

	json.Unmarshal(data, &initOutput)
	decodeIv, _ := base64.StdEncoding.DecodeString(initOutput.Data.Iv)
	decodePayload, _ := base64.StdEncoding.DecodeString(initOutput.Data.Payload)

	data, err = aesDecrypt(secretKey, decodeIv, decodePayload)

	if err != nil {
		log.Println("Error:", err)
	}
	var challengeOutput challengeAuth

	err = json.Unmarshal(data, &challengeOutput)
	if err != nil {
		log.Println("Error:", err)
	}

	seshKey := challengeOutput.Challenge.SessionKey
	initId := challengeOutput.Challenge.InitialActionId

	return seshKey, initId
}

func aesDecrypt(key []byte, iv []byte, payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("Error:", err)
	}
	if len(iv) < aes.BlockSize {
		panic("payload too short")
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(payload, payload)

	blockSize := cbc.BlockSize()

	// Remove PKCS7 padding
	payloadLen := len(payload)
	paddingLen := int(payload[payloadLen-1])
	if paddingLen >= payloadLen || paddingLen > blockSize {
		return nil, err
	}
	return payload[:payloadLen-paddingLen], nil
}

func getDoorStatus(c *websocket.Conn, secretKey []byte, authKey []byte, seshKey string, initId int) string {
	initId = initId + 1
	query := fmt.Sprintf("{\"action\":{\"type\":\"QUERY\",\"id\":%v}}", initId)

	var payload []byte

	payload, err := aesEncryptWithSeshKey(authKey, []byte(seshKey), []byte(query))
	if err != nil {
		log.Println("Error:", err)
	}

	err = c.WriteMessage(websocket.TextMessage, payload)
	if err != nil {
		log.Println("Error:", err)
	}

	data, err := readResponse(c)
	if err != nil {
		log.Println("Error:", err)
	}
	var output encryptedRequest
	json.Unmarshal(data, &output)

	decodeIv, _ := base64.StdEncoding.DecodeString(output.Data.Iv)
	decodePayload, _ := base64.StdEncoding.DecodeString(output.Data.Payload)
	decodeSeshKey, _ := base64.StdEncoding.DecodeString(seshKey)

	unencryptedData, _ := aesDecrypt(decodeSeshKey, decodeIv, decodePayload)

	var unencryptedDataJson doorStatus
	json.Unmarshal(unencryptedData, &unencryptedDataJson)

	return unencryptedDataJson.Response.State
}

func aesEncryptWithSeshKey(authKey []byte, key []byte, payload []byte) ([]byte, error) {
	newKey, _ := base64.StdEncoding.DecodeString(string(key))
	block, err := aes.NewCipher(newKey)
	if err != nil {
		log.Println("Error:", err)
	}
	iv := payload[:aes.BlockSize]
	ivB64 := base64.StdEncoding.EncodeToString(iv)

	cbc := cipher.NewCBCDecrypter(block, iv)

	// Add PKCS7 padding
	blockSize := cbc.BlockSize()
	payloadLen := len(payload)
	padLen := blockSize - (payloadLen % blockSize)
	padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
	paddedLoad := append(payload, padText...)

	// Encrypt the payload
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(paddedLoad, paddedLoad)

	payloadJson, _ := json.Marshal(paddedLoad)
	payloadJson2, _ := strconv.Unquote(string(payloadJson))

	payloadB64 := base64.StdEncoding.EncodeToString(paddedLoad)

	// Generate HMAC
	hmacPayload := &data{
		Iv:      ivB64,
		Payload: payloadJson2,
	}

	hmacPayloadJson, _ := json.Marshal(hmacPayload)

	hmacData := hmac.New(sha256.New, authKey)
	hmacData.Write([]byte(hmacPayloadJson))
	hmacHash := hmacData.Sum(nil)
	hmacHashB64 := base64.StdEncoding.EncodeToString([]byte(hmacHash))

	requestPayload := &encryptedRequest{
		Type: "ENCRYPTED",
		Data: data{
			Iv:      ivB64,
			Payload: payloadB64,
		},
		Mac: hmacHashB64,
	}
	requestPayloadJson, _ := json.Marshal(requestPayload)

	return requestPayloadJson, nil

}

func getSecret(secretName string) (string, error) {
	conf := api.DefaultConfig()
	client, _ = api.NewClient(conf)
	client.SetAddress(vault_addr)
	// Get auth from Vault
	resp, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   role_id,
		"secret_id": secret_id,
	})
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	if resp == nil {
		fmt.Println("empty response from credential provider")
		return "", err
	}

	// Set client token for Vault
	client.SetToken(resp.Auth.ClientToken)
	secret, err := client.Logical().Read("remootio/data/access")
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	key, _ := secret.Data["data"].(map[string]interface{})
	keyreturn := fmt.Sprintf("%v", key[secretName])
	return keyreturn, nil
}
