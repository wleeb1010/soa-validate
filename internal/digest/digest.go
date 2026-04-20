package digest

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Hex returns lowercase hex of sha256(data). This matches the spec's
// build-manifest.mjs digest convention.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SHA256 returns the raw 32-byte digest.
func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}
