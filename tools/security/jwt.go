package security

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

var Private_key []byte
var Public_key []byte

// init: Creates a private key and a public key for JWT signing if they don't exist on disk
func init() {
	home_dir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	var make_keys bool = false
	// Check path: ~/.config/runawayvpn/keys/signing/...
	// If exists, load keys
	if _, err := os.Stat(home_dir + "/.config/runawayvpn/keys/signing/private.key"); err == nil {
		// Read private key
		Private_key, err = os.ReadFile(home_dir + "/.config/runawayvpn/keys/signing/private.key")
		if err != nil {
			make_keys = true
		}
	} else {
		make_keys = true
	}
	if _, err := os.Stat(home_dir + "/.config/runawayvpn/keys/signing/public.key"); err == nil {
		// Read public key
		Public_key, err = os.ReadFile(home_dir + "/.config/runawayvpn/keys/signing/public.key")
		if err != nil {
			make_keys = true
		}
	} else {
		make_keys = true
	}
	if make_keys {
		// Generate keys
		Public_key, Private_key = DGenerateKeyPair()
		// Make directory if it doesn't exist
		err := os.MkdirAll(home_dir+"/.config/runawayvpn/keys/signing", 0755)
		if err != nil {
			panic(err)
		}
		// Write keys to disk
		err = os.WriteFile(home_dir+"/.config/runawayvpn/keys/signing/private.key", Private_key, 0644)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(home_dir+"/.config/runawayvpn/keys/signing/public.key", Public_key, 0644)
		if err != nil {
			panic(err)
		}
	}

}

// CreateToken builds a JWT token
func CreateToken(payload string) (string, error) {
	// Create header
	header := map[string]interface{}{
		"alg": "dilithium",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := EncodeBS(headerJSON)

	// Encode payload
	payloadB64 := EncodeSS(payload)

	// Sign token
	signature := DSign(Private_key, append(headerJSON, []byte(payload)...))

	// Encode signature
	signatureB64 := EncodeBS(signature)

	// Return token
	return headerB64 + "." + payloadB64 + "." + signatureB64, nil
}

// VerifyToken verifies a JWT token and returns the payload
func VerifyToken(token string) (interface{}, error) {
	// Decode header, payload, and signature
	headerB64, payloadB64, signatureB64, err := SplitToken(token)
	if err != nil {
		return nil, err
	}
	headerBytes, err := DecodeSB(headerB64)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := DecodeSB(payloadB64)
	if err != nil {
		return nil, err
	}
	signature, err := DecodeSB(signatureB64)
	if err != nil {
		return nil, err
	}

	// Verify signature
	if !DVerify(Public_key, append(headerBytes, payloadBytes...), signature) {
		return nil, errors.New("invalid signature")
	}

	// Decode payload
	var payload interface{}
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// SplitToken decodes a JWT token into its header, payload, and signature
func SplitToken(token string) (string, string, string, error) {
	// Split token into header, payload, and signature
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return "", "", "", errors.New("invalid token")
	}
	headerB64 := split[0]
	payloadB64 := split[1]
	signatureB64 := split[2]

	return headerB64, payloadB64, signatureB64, nil
}
