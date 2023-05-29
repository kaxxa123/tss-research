package main

import (
	"encoding/hex"
	"math/big"

	"golang.org/x/crypto/sha3"
)

func padBytes(bytes []byte) []byte {
	paddedBytes := make([]byte, 32)
	copy(paddedBytes[32-len(bytes):], bytes)
	return paddedBytes
}

func uncompressedPK(x, y *big.Int) string {
	// Concatenate x and y coordinates
	pubKeyBytes := append(padBytes(x.Bytes()), padBytes(y.Bytes())...)

	// Prepend 0x04 byte
	pubKeyBytes = append([]byte{0x04}, pubKeyBytes...)

	// Convert to hexadecimal representation
	publicKeyHex := hex.EncodeToString(pubKeyBytes)

	return publicKeyHex
}

func pk2addr(publicKeyHex string) string {
	// Decode the hexadecimal representation of the uncompressed public key
	pkBytes, _ := hex.DecodeString(publicKeyHex)

	// Compute Keccak-256 hash
	hash := sha3.New256()
	hash.Write(pkBytes)
	hashBytes := hash.Sum(nil)

	// Take last 20 bytes
	addressBytes := hashBytes[len(hashBytes)-20:]
	address := "0x" + hex.EncodeToString(addressBytes)
	return address
}
