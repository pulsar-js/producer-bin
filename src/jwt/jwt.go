package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

func Verify(token string, log *logrus.Logger) (string, bool, error) {
	if !strings.HasPrefix(token, "eyJ") {
		data, err := os.ReadFile(token)
		if err != nil {
			return "", false, err
		}
		token = string(data)
	}

	// Parse
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token, false, fmt.Errorf("failed to parse JWT")
	}

	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return token, false, fmt.Errorf("failed to decode header: %w", err)
	}
	payloadJSON, err := decodeSegment(parts[1])
	if err != nil {
		return token, false, fmt.Errorf("failed to decode payload: %w", err)
	}

	var header, payload map[string]any
	if err = json.Unmarshal(headerJSON, &header); err != nil {
		return token, false, fmt.Errorf("failed to unmarshal header: %w", err)
	}
	if err = json.Unmarshal(payloadJSON, &payload); err != nil {
		return token, false, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	log.WithFields(logrus.Fields{
		"raw":     token,
		"header":  header,
		"payload": payload,
	}).Info("parsed jwt")

	// Verify
	if kid, exists := header["kid"]; exists {
		if jku, exists := header["jku"]; exists {
			resp, err := http.Get(jku.(string))
			if err != nil {
				return token, false, fmt.Errorf("failed to fetch JWKs: %w", err)
			}
			defer resp.Body.Close()

			var data map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				return token, false, fmt.Errorf("failed to decode JWKs: %w", err)
			}

			if keys, ok := data["keys"].([]interface{}); ok {
				for _, key := range keys {
					if keyMap, ok := key.(map[string]interface{}); ok {
						if kid == keyMap["kid"] {
							if err := verify(token, keyMap); err != nil {
								return token, false, fmt.Errorf("failed to verify signature: %w", err)
							}

							log.Info("signature verified")

							return token, true, nil
						}
					}
				}
			}
		}
	}

	log.Warn("jwt verification failed")

	return token, false, nil
}

func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}

func verify(jwt string, jwk map[string]any) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token")
	}

	// optional: ensure verify is allowed
	if ops, ok := jwk["key_ops"].([]any); ok {
		allowed := false
		for _, v := range ops {
			if s, ok := v.(string); ok && s == "verify" {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("jwk key_ops does not include verify")
		}
	}

	xVal, ok := jwk["x"].(string)
	if !ok {
		return fmt.Errorf("missing x")
	}
	yVal, ok := jwk["y"].(string)
	if !ok {
		return fmt.Errorf("missing y")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xVal)
	if err != nil {
		return fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yVal)
	if err != nil {
		return fmt.Errorf("decode y: %w", err)
	}

	pub := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != 64 {
		return fmt.Errorf("unexpected signature length %d", len(sig))
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	if !ecdsa.Verify(&pub, hash[:], r, s) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}
