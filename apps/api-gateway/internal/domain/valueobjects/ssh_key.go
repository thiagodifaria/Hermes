package valueobjects

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHKeyType represents different SSH key types
type SSHKeyType string

const (
	SSHKeyTypeRSA     SSHKeyType = "ssh-rsa"
	SSHKeyTypeEd25519 SSHKeyType = "ssh-ed25519"
	SSHKeyTypeECDSA   SSHKeyType = "ecdsa-sha2-nistp256"
	SSHKeyTypeDSS     SSHKeyType = "ssh-dss"
)

// SSHKey represents a validated SSH public key value object
type SSHKey struct {
	keyType     SSHKeyType
	keyData     string
	comment     string
	fingerprint string
	bitLength   int
	algorithm   string
	createdAt   time.Time
}

// SSH key validation errors
var (
	ErrEmptySSHKey       = errors.New("SSH key cannot be empty")
	ErrInvalidSSHKeyFormat = errors.New("invalid SSH key format")
	ErrUnsupportedKeyType  = errors.New("unsupported SSH key type")
	ErrWeakSSHKey        = errors.New("SSH key is too weak")
	ErrInvalidKeyData    = errors.New("invalid SSH key data")
	ErrKeyTooShort       = errors.New("SSH key is too short")
)

// SSH key security requirements
const (
	MinRSAKeyLength     = 2048
	RecommendedRSAKeyLength = 4096
	MinECDSAKeyLength   = 256
	Ed25519KeyLength    = 256
)

// SSH key format regex
var sshKeyRegex = regexp.MustCompile(`^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ssh-dss)\s+([A-Za-z0-9+/]+={0,2})\s*(.*)$`)

// NewSSHKey creates a new SSH key value object with validation
func NewSSHKey(keyString string) (SSHKey, error) {
	// Trim whitespace
	keyString = strings.TrimSpace(keyString)
	
	// Check if empty
	if keyString == "" {
		return SSHKey{}, ErrEmptySSHKey
	}
	
	// Parse SSH key format
	matches := sshKeyRegex.FindStringSubmatch(keyString)
	if len(matches) != 4 {
		return SSHKey{}, ErrInvalidSSHKeyFormat
	}
	
	keyType := SSHKeyType(matches[1])
	keyData := matches[2]
	comment := strings.TrimSpace(matches[3])
	
	// Validate key type
	if !isValidKeyType(keyType) {
		return SSHKey{}, ErrUnsupportedKeyType
	}
	
	// Decode and validate key data
	keyBytes, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return SSHKey{}, ErrInvalidKeyData
	}
	
	// Parse the key using Go's SSH library
	publicKey, err := ssh.ParsePublicKey(keyBytes)
	if err != nil {
		return SSHKey{}, ErrInvalidSSHKeyFormat
	}
	
	// Extract key information
	bitLength := getKeyBitLength(publicKey)
	algorithm := string(keyType)
	
	// Validate key strength
	if err := validateKeyStrength(keyType, bitLength); err != nil {
		return SSHKey{}, err
	}
	
	// Generate fingerprints
	fingerprint := generateFingerprint(publicKey)
	
	sshKey := SSHKey{
		keyType:     keyType,
		keyData:     keyData,
		comment:     comment,
		fingerprint: fingerprint,
		bitLength:   bitLength,
		algorithm:   algorithm,
		createdAt:   time.Now(),
	}
	
	return sshKey, nil
}

// MustNewSSHKey creates a new SSH key and panics on error
func MustNewSSHKey(keyString string) SSHKey {
	sshKey, err := NewSSHKey(keyString)
	if err != nil {
		panic(err)
	}
	return sshKey
}

// GetKeyType returns the SSH key type
func (k SSHKey) GetKeyType() SSHKeyType {
	return k.keyType
}

// GetKeyData returns the base64-encoded key data
func (k SSHKey) GetKeyData() string {
	return k.keyData
}

// GetComment returns the key comment
func (k SSHKey) GetComment() string {
	return k.comment
}

// GetFingerprint returns the key fingerprint
func (k SSHKey) GetFingerprint() string {
	return k.fingerprint
}

// GetBitLength returns the key bit length
func (k SSHKey) GetBitLength() int {
	return k.bitLength
}

// GetAlgorithm returns the key algorithm
func (k SSHKey) GetAlgorithm() string {
	return k.algorithm
}

// GetCreatedAt returns when the key was created
func (k SSHKey) GetCreatedAt() time.Time {
	return k.createdAt
}

// ToString returns the full SSH key string
func (k SSHKey) ToString() string {
	if k.comment != "" {
		return fmt.Sprintf("%s %s %s", k.keyType, k.keyData, k.comment)
	}
	return fmt.Sprintf("%s %s", k.keyType, k.keyData)
}

// String returns the string representation
func (k SSHKey) String() string {
	return k.ToString()
}

// IsEmpty checks if the key is empty
func (k SSHKey) IsEmpty() bool {
	return k.keyData == ""
}

// Equals checks if two SSH keys are equal
func (k SSHKey) Equals(other SSHKey) bool {
	return k.fingerprint == other.fingerprint
}

// IsRSA checks if the key is RSA type
func (k SSHKey) IsRSA() bool {
	return k.keyType == SSHKeyTypeRSA
}

// IsEd25519 checks if the key is Ed25519 type
func (k SSHKey) IsEd25519() bool {
	return k.keyType == SSHKeyTypeEd25519
}

// IsECDSA checks if the key is ECDSA type
func (k SSHKey) IsECDSA() bool {
	return k.keyType == SSHKeyTypeECDSA
}

// IsDSS checks if the key is DSS type
func (k SSHKey) IsDSS() bool {
	return k.keyType == SSHKeyTypeDSS
}

// IsSecure checks if the key meets current security standards
func (k SSHKey) IsSecure() bool {
	switch k.keyType {
	case SSHKeyTypeRSA:
		return k.bitLength >= RecommendedRSAKeyLength
	case SSHKeyTypeEd25519:
		return true // Ed25519 is always secure
	case SSHKeyTypeECDSA:
		return k.bitLength >= MinECDSAKeyLength
	case SSHKeyTypeDSS:
		return false // DSS is considered insecure
	default:
		return false
	}
}

// GetSecurityLevel returns the security level of the key
func (k SSHKey) GetSecurityLevel() string {
	if !k.IsSecure() {
		return "weak"
	}
	
	switch k.keyType {
	case SSHKeyTypeEd25519:
		return "excellent"
	case SSHKeyTypeRSA:
		if k.bitLength >= 4096 {
			return "excellent"
		}
		return "good"
	case SSHKeyTypeECDSA:
		return "good"
	default:
		return "weak"
	}
}

// GetMD5Fingerprint returns the MD5 fingerprint (legacy format)
func (k SSHKey) GetMD5Fingerprint() string {
	keyBytes, err := base64.StdEncoding.DecodeString(k.keyData)
	if err != nil {
		return ""
	}
	
	hash := md5.Sum(keyBytes)
	var parts []string
	for _, b := range hash {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	
	return strings.Join(parts, ":")
}

// GetSHA256Fingerprint returns the SHA256 fingerprint
func (k SSHKey) GetSHA256Fingerprint() string {
	keyBytes, err := base64.StdEncoding.DecodeString(k.keyData)
	if err != nil {
		return ""
	}
	
	hash := sha256.Sum256(keyBytes)
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}

// GetShortFingerprint returns a shortened version of the fingerprint
func (k SSHKey) GetShortFingerprint() string {
	if len(k.fingerprint) > 16 {
		return k.fingerprint[:16] + "..."
	}
	return k.fingerprint
}

// WithComment creates a new SSH key with updated comment
func (k SSHKey) WithComment(comment string) SSHKey {
	newKey := k
	newKey.comment = comment
	return newKey
}

// GetKeyInfo returns detailed information about the key
func (k SSHKey) GetKeyInfo() map[string]interface{} {
	return map[string]interface{}{
		"type":            string(k.keyType),
		"algorithm":       k.algorithm,
		"bit_length":      k.bitLength,
		"fingerprint":     k.fingerprint,
		"md5_fingerprint": k.GetMD5Fingerprint(),
		"sha256_fingerprint": k.GetSHA256Fingerprint(),
		"comment":         k.comment,
		"security_level":  k.GetSecurityLevel(),
		"is_secure":       k.IsSecure(),
		"created_at":      k.createdAt,
	}
}

// Validate performs additional validation on the key
func (k SSHKey) Validate() error {
	if k.IsEmpty() {
		return ErrEmptySSHKey
	}
	
	if !k.IsSecure() {
		return ErrWeakSSHKey
	}
	
	return nil
}

// isValidKeyType checks if the key type is supported
func isValidKeyType(keyType SSHKeyType) bool {
	validTypes := []SSHKeyType{
		SSHKeyTypeRSA,
		SSHKeyTypeEd25519,
		SSHKeyTypeECDSA,
		SSHKeyTypeDSS,
	}
	
	for _, validType := range validTypes {
		if keyType == validType {
			return true
		}
	}
	
	return false
}

// validateKeyStrength validates if the key meets minimum security requirements
func validateKeyStrength(keyType SSHKeyType, bitLength int) error {
	switch keyType {
	case SSHKeyTypeRSA:
		if bitLength < MinRSAKeyLength {
			return ErrWeakSSHKey
		}
	case SSHKeyTypeECDSA:
		if bitLength < MinECDSAKeyLength {
			return ErrWeakSSHKey
		}
	case SSHKeyTypeEd25519:
		// Ed25519 keys are always 256 bits and secure
		return nil
	case SSHKeyTypeDSS:
		// DSS keys are considered insecure
		return ErrWeakSSHKey
	default:
		return ErrUnsupportedKeyType
	}
	
	return nil
}

// getKeyBitLength extracts the bit length from a public key
func getKeyBitLength(publicKey ssh.PublicKey) int {
	switch key := publicKey.(type) {
	case *ssh.rsaPublicKey:
		return key.N.BitLen()
	case ssh.CryptoPublicKey:
		// For ECDSA and Ed25519 keys, we need to determine based on type
		switch publicKey.Type() {
		case "ssh-ed25519":
			return Ed25519KeyLength
		case "ecdsa-sha2-nistp256":
			return 256
		case "ecdsa-sha2-nistp384":
			return 384
		case "ecdsa-sha2-nistp521":
			return 521
		}
	}
	
	return 0
}

// generateFingerprint generates a SHA256 fingerprint for the key
func generateFingerprint(publicKey ssh.PublicKey) string {
	hash := sha256.Sum256(publicKey.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}

// ParseSSHKeys parses multiple SSH keys from a string (e.g., authorized_keys format)
func ParseSSHKeys(keysString string) ([]SSHKey, error) {
	var keys []SSHKey
	var errors []error
	
	lines := strings.Split(keysString, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		key, err := NewSSHKey(line)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		
		keys = append(keys, key)
	}
	
	if len(errors) > 0 && len(keys) == 0 {
		return nil, fmt.Errorf("failed to parse any SSH keys: %v", errors[0])
	}
	
	return keys, nil
}

// ValidateSSHKeyFile validates an SSH public key file format
func ValidateSSHKeyFile(content string) error {
	keys, err := ParseSSHKeys(content)
	if err != nil {
		return err
	}
	
	if len(keys) == 0 {
		return errors.New("no valid SSH keys found")
	}
	
	return nil
}

// CompareSSHKeys compares two SSH keys for equality
func CompareSSHKeys(key1, key2 SSHKey) bool {
	return key1.Equals(key2)
}

// GetRecommendedKeyTypes returns the recommended SSH key types in order of preference
func GetRecommendedKeyTypes() []SSHKeyType {
	return []SSHKeyType{
		SSHKeyTypeEd25519,
		SSHKeyTypeECDSA,
		SSHKeyTypeRSA,
		// DSS is not recommended
	}
}

// IsRecommendedKeyType checks if the key type is recommended
func IsRecommendedKeyType(keyType SSHKeyType) bool {
	recommended := GetRecommendedKeyTypes()
	for _, rec := range recommended {
		if keyType == rec {
			return true
		}
	}
	return false
}

// GenerateSSHKeyComment generates a default comment for an SSH key
func GenerateSSHKeyComment(username, hostname string) string {
	if username != "" && hostname != "" {
		return fmt.Sprintf("%s@%s", username, hostname)
	}
	if username != "" {
		return username
	}
	return fmt.Sprintf("generated-%d", time.Now().Unix())
}