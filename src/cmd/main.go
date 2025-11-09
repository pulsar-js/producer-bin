package main

import (
	"fmt"
	"os"
	"pulsar-js/commands"

	"github.com/alecthomas/kong"
)

var (
	name        string
	version     string
	description string
	buildTime   string
	debug       string
)

func main() {
	cmd := &commands.Context{
		Debug: (debug == "true"),
	}
	cmd.Set("name", name)
	cmd.Set("version", version)
	cmd.Set("description", description)
	cmd.Set("buildTime", buildTime)

	var app commands.App

	ctx := kong.Parse(
		&app,
		kong.Name(name),
		kong.Description(description+"\nv"+version),
		kong.UsageOnError(),
		kong.HelpOptions{
			Compact: true,
		},
	)

	err := ctx.Run(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// func main() {
// 	num := "0"
// 	if len(os.Args) > 1 {
// 		num = os.Args[1]
// 	}

// 	var jwt string
// 	if len(os.Args) > 2 {
// 		data, err := os.ReadFile(os.Args[2])
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		jwt = string(data)
// 	}

// 	if jwt != "" {
// 		parts := strings.Split(jwt, ".")
// 		if len(parts) < 2 {
// 			panic("invalid JWT")
// 		}
// 		headerJSON, _ := decodeSegment(parts[0])
// 		payloadJSON, _ := decodeSegment(parts[1])

// 		var header, payload map[string]any
// 		_ = json.Unmarshal(headerJSON, &header)
// 		_ = json.Unmarshal(payloadJSON, &payload)

// 		out, _ := json.MarshalIndent(header, "", "  ")
// 		fmt.Println("\nJWT\n----------------------")
// 		fmt.Println("header:", string(out))
// 		out, _ = json.MarshalIndent(payload, "", "  ")
// 		fmt.Println("payload:", string(out))

// 		if kid, exists := header["kid"]; exists {
// 			if jku, exists := header["jku"]; exists {
// 				resp, err := http.Get(jku.(string))
// 				if err != nil {
// 					panic(err)
// 				}
// 				defer resp.Body.Close()

// 				var data map[string]interface{}
// 				if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
// 					panic(err)
// 				}

// 				for _, key := range data["keys"].([]interface{}) {
// 					jwk := key.(map[string]interface{})
// 					if jwk["kid"] == kid {
// 						if err := verify(jwt, jwk); err != nil {
// 							fmt.Println("\nVERIFICATION FAILED\n\n")
// 							fmt.Println(err)
// 							os.Exit(1)
// 						}
// 						fmt.Println("\nSIGNATURE VERIFIED\n\n")
// 						break
// 					}
// 				}
// 			}
// 		}
// 	}

// 	var uri string
// 	switch num {
// 	case "1":
// 		fmt.Println("Using pulse node 1 (152.53.164.33)")
// 		uri = "pulsar://152.53.164.33:6650"
// 	case "2":
// 		fmt.Println("Using pulse node 2 (152.53.166.34)")
// 		uri = "pulsar://152.53.166.34:6650"
// 	case "3":
// 		fmt.Println("Using floating IP (152.53.31.83)")
// 		uri = "pulsar+ssl://152.53.31.83:6651"
// 	case "l", "local":
// 		fmt.Println("Using local pulsar")
// 		uri = "pulsar://localhost:6650"
// 	case "d", "dns":
// 		fmt.Println("Using DNS entry (pulse.author.io)")
// 		uri = "pulsar+ssl://pulse.author.io:6651"
// 	default:
// 		fmt.Printf("Using %s\n", num)
// 		uri = "pulsar+ssl://" + num + ":6651"
// 	}

// 	// Create a new token authentication provider
// 	// jwtToken := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1bHNlLTIwMjUxMDIxIiwiamt1IjoiaHR0cHM6Ly9saWNlbnNpbmcuYXV0aG9yLmlvLy53ZWxsLWtub3duL2p3a3MifQ.eyJpc3MiOiJodHRwczovL2xpY2Vuc2luZy5hdXRob3IuaW8iLCJzdWIiOiJBMDFLN1NTQlg4OVA5VFFDSkdHRjI2TkhROEciLCJqdGkiOiIwMUs4MjZSU1JHUkcxRDNONFJEMkQ5VDhCTSIsImlhdCI6MTc2MTAxMDgwNCwiZXhwIjoxNzYxMDk3MjA0LCJuYmYiOjE3NjEwMTA4MDQsImF1ZCI6InB1bHNlIiwiYWN0IjoiMDFLN1NTQlg4OUE4SjRZRUFFOTc5R05QUlYiLCJyb2xlcyI6WyJwdWJsaWMvYXV0aG9yIiwicHVibGljL2pzLXJ1bnRpbWUiLCJwcml2YXRlL2FjY291bnQvQTAxSzdTU0JYODlQOVRRQ0pHR0YyNk5IUThHIl19.Gx0VvbBIa4rHk0-SyMr9zuwBOvkgMxifjRhh1XVaZ-smFb4jhcVNhwHHBo7OY_ch8VAxD9_b4B64Ho_dno8mCA"
// 	jwtToken := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1bHNlLTIwMjUxMDI0Iiwiamt1IjoiaHR0cHM6Ly9saWNlbnNpbmcuYXV0aG9yLmlvLy53ZWxsLWtub3duL2p3a3MifQ.eyJpc3MiOiJodHRwczovL2xpY2Vuc2luZy5hdXRob3IuaW8iLCJzdWIiOiJBMDFLN1NTQlg4OVA5VFFDSkdHRjI2TkhROEciLCJqdGkiOiIwMUs4QlRRVDFKVzAwRVdOTlBFUkcwUUVSMCIsImlhdCI6MTc2MTMzMzczMywiZXhwIjoxNzYxNDIwMTMzLCJuYmYiOjE3NjEzMzM3MzMsImF1ZCI6InB1bHNlIiwiYWN0IjoiMDFLN1NTQlg4OUE4SjRZRUFFOTc5R05QUlYiLCJyb2xlcyI6WyJwdWJsaWMvYXV0aG9yIiwicHVibGljL2pzLXJ1bnRpbWUiLCJwcml2YXRlL2FjY291bnQvQTAxSzdTU0JYODlQOVRRQ0pHR0YyNk5IUThHIl19.QTsPyor9nVgZpWDahARfAnV54McezWRLApzg58OIJJcG2MOhSRQlKLoVzrpUj8Tf7r9bDzON3zuA0NWqpEZFaw"
// 	if jwt != "" {
// 		jwtToken = jwt

// 	}
// 	auth := pulsar.NewAuthenticationToken(jwtToken)

// 	// Connect to broker
// 	client, err := pulsar.NewClient(pulsar.ClientOptions{
// 		URL: uri,
// 		// TLSAllowInsecureConnection: true,
// 		// TLSValidateHostname:        false,
// 		Authentication: auth,
// 		// CustomMetricsLabels:       map[string]string{"app": "pulsar-go-client", "version": version},
// 	})
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer client.Close()

// 	// Create producer
// 	producer, err := client.CreateProducer(pulsar.ProducerOptions{
// 		Topic: "persistent://public/default/test",
// 	})
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer producer.Close()

// 	// // Send message
// 	_, err = producer.Send(context.Background(), &pulsar.ProducerMessage{
// 		Payload: []byte("hello"),
// 	})
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fmt.Println("Message sent")

// 	// Create consumer
// 	consumer, err := client.Subscribe(pulsar.ConsumerOptions{
// 		Topic:            "persistent://public/default/test",
// 		SubscriptionName: "test-subscription",
// 		Type:             pulsar.Shared,
// 	})
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer consumer.Close()

// 	// Receive message
// 	for {
// 		msg, err := consumer.Receive(context.Background())
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		fmt.Printf("Received message msgId: %v -- content: '%s'\n", msg.ID(), string(msg.Payload()))

// 		// Acknowledge
// 		consumer.Ack(msg)
// 	}
// }

// func decodeSegment(seg string) ([]byte, error) {
// 	return base64.RawURLEncoding.DecodeString(seg)
// }

// func verify(jwt string, jwk map[string]any) error {
// 	parts := strings.Split(jwt, ".")
// 	if len(parts) != 3 {
// 		return fmt.Errorf("invalid token")
// 	}

// 	// optional: ensure verify is allowed
// 	if ops, ok := jwk["key_ops"].([]any); ok {
// 		allowed := false
// 		for _, v := range ops {
// 			if s, ok := v.(string); ok && s == "verify" {
// 				allowed = true
// 				break
// 			}
// 		}
// 		if !allowed {
// 			return fmt.Errorf("jwk key_ops does not include verify")
// 		}
// 	}

// 	xVal, ok := jwk["x"].(string)
// 	if !ok {
// 		return fmt.Errorf("missing x")
// 	}
// 	yVal, ok := jwk["y"].(string)
// 	if !ok {
// 		return fmt.Errorf("missing y")
// 	}

// 	xBytes, err := base64.RawURLEncoding.DecodeString(xVal)
// 	if err != nil {
// 		return fmt.Errorf("decode x: %w", err)
// 	}
// 	yBytes, err := base64.RawURLEncoding.DecodeString(yVal)
// 	if err != nil {
// 		return fmt.Errorf("decode y: %w", err)
// 	}

// 	pub := ecdsa.PublicKey{
// 		Curve: elliptic.P256(),
// 		X:     new(big.Int).SetBytes(xBytes),
// 		Y:     new(big.Int).SetBytes(yBytes),
// 	}

// 	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
// 	if err != nil {
// 		return fmt.Errorf("decode signature: %w", err)
// 	}
// 	if len(sig) != 64 {
// 		return fmt.Errorf("unexpected signature length %d", len(sig))
// 	}

// 	r := new(big.Int).SetBytes(sig[:32])
// 	s := new(big.Int).SetBytes(sig[32:])
// 	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

// 	if !ecdsa.Verify(&pub, hash[:], r, s) {
// 		return fmt.Errorf("signature invalid")
// 	}
// 	return nil
// }
