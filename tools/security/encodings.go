package security

import "encoding/base64"

// EncodeBS encodes a byte slice to a base64 string
func EncodeBS(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeSB decodes a base64 string to a byte slice
func DecodeSB(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
