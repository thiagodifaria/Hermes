package valueobjects

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IPAddressType represents the type of IP address
type IPAddressType string

const (
	IPv4 IPAddressType = "ipv4"
	IPv6 IPAddressType = "ipv6"
)

// IPAddress represents a validated IP address value object
type IPAddress struct {
	value   string
	ipType  IPAddressType
	network *net.IP
	isPrivate bool
	isLoopback bool
	isMulticast bool
}

// IP address validation errors
var (
	ErrEmptyIPAddress    = errors.New("IP address cannot be empty")
	ErrInvalidIPAddress  = errors.New("invalid IP address format")
	ErrPrivateIPNotAllowed = errors.New("private IP addresses are not allowed")
	ErrLoopbackNotAllowed = errors.New("loopback addresses are not allowed")
	ErrMulticastNotAllowed = errors.New("multicast addresses are not allowed")
)

// Private IP address ranges (RFC 1918 and others)
var privateIPv4Ranges = []*net.IPNet{}
var privateIPv6Ranges = []*net.IPNet{}

func init() {
	// Initialize private IPv4 ranges
	privateCIDRs := []string{
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // RFC 3927 (Link-local)
		"127.0.0.0/8",    // Loopback
	}
	
	for _, cidr := range privateCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateIPv4Ranges = append(privateIPv4Ranges, network)
		}
	}
	
	// Initialize private IPv6 ranges
	privateIPv6CIDRs := []string{
		"fc00::/7",  // RFC 4193 (Unique Local)
		"fe80::/10", // RFC 4291 (Link-local)
		"::1/128",   // Loopback
	}
	
	for _, cidr := range privateIPv6CIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateIPv6Ranges = append(privateIPv6Ranges, network)
		}
	}
}

// NewIPAddress creates a new IP address value object with validation
func NewIPAddress(address string) (IPAddress, error) {
	// Trim whitespace
	address = strings.TrimSpace(address)
	
	// Check if empty
	if address == "" {
		return IPAddress{}, ErrEmptyIPAddress
	}
	
	// Parse IP address
	ip := net.ParseIP(address)
	if ip == nil {
		return IPAddress{}, ErrInvalidIPAddress
	}
	
	// Determine IP type
	var ipType IPAddressType
	if ip.To4() != nil {
		ipType = IPv4
		// Normalize IPv4 address (remove leading zeros)
		address = ip.To4().String()
	} else {
		ipType = IPv6
		// Normalize IPv6 address
		address = ip.String()
	}
	
	// Check IP characteristics
	isPrivate := isPrivateIP(ip)
	isLoopback := ip.IsLoopback()
	isMulticast := ip.IsMulticast()
	
	ipAddress := IPAddress{
		value:       address,
		ipType:      ipType,
		network:     &ip,
		isPrivate:   isPrivate,
		isLoopback:  isLoopback,
		isMulticast: isMulticast,
	}
	
	return ipAddress, nil
}

// NewPublicIPAddress creates a new IP address that must be public (not private/loopback)
func NewPublicIPAddress(address string) (IPAddress, error) {
	ipAddr, err := NewIPAddress(address)
	if err != nil {
		return IPAddress{}, err
	}
	
	if ipAddr.isPrivate {
		return IPAddress{}, ErrPrivateIPNotAllowed
	}
	
	if ipAddr.isLoopback {
		return IPAddress{}, ErrLoopbackNotAllowed
	}
	
	if ipAddr.isMulticast {
		return IPAddress{}, ErrMulticastNotAllowed
	}
	
	return ipAddr, nil
}

// MustNewIPAddress creates a new IP address and panics on error
func MustNewIPAddress(address string) IPAddress {
	ipAddr, err := NewIPAddress(address)
	if err != nil {
		panic(err)
	}
	return ipAddr
}

// String returns the string representation of the IP address
func (ip IPAddress) String() string {
	return ip.value
}

// Value returns the IP address value
func (ip IPAddress) Value() string {
	return ip.value
}

// Type returns the IP address type (IPv4 or IPv6)
func (ip IPAddress) Type() IPAddressType {
	return ip.ipType
}

// IsIPv4 checks if the address is IPv4
func (ip IPAddress) IsIPv4() bool {
	return ip.ipType == IPv4
}

// IsIPv6 checks if the address is IPv6
func (ip IPAddress) IsIPv6() bool {
	return ip.ipType == IPv6
}

// IsPrivate checks if the address is in a private range
func (ip IPAddress) IsPrivate() bool {
	return ip.isPrivate
}

// IsPublic checks if the address is public (not private, loopback, or multicast)
func (ip IPAddress) IsPublic() bool {
	return !ip.isPrivate && !ip.isLoopback && !ip.isMulticast
}

// IsLoopback checks if the address is a loopback address
func (ip IPAddress) IsLoopback() bool {
	return ip.isLoopback
}

// IsMulticast checks if the address is a multicast address
func (ip IPAddress) IsMulticast() bool {
	return ip.isMulticast
}

// IsEmpty checks if the IP address is empty
func (ip IPAddress) IsEmpty() bool {
	return ip.value == ""
}

// Equals checks if two IP addresses are equal
func (ip IPAddress) Equals(other IPAddress) bool {
	return ip.value == other.value
}

// GetNetwork returns the underlying net.IP
func (ip IPAddress) GetNetwork() *net.IP {
	return ip.network
}

// IsInRange checks if the IP address is within a given CIDR range
func (ip IPAddress) IsInRange(cidr string) (bool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, err
	}
	
	return network.Contains(*ip.network), nil
}

// GetSubnet returns the subnet portion for a given CIDR
func (ip IPAddress) GetSubnet(cidr string) (string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	
	if network.Contains(*ip.network) {
		return network.String(), nil
	}
	
	return "", errors.New("IP address not in specified subnet")
}

// Reverse returns the reverse DNS notation of the IP address
func (ip IPAddress) Reverse() string {
	if ip.IsIPv4() {
		parts := strings.Split(ip.value, ".")
		if len(parts) != 4 {
			return ""
		}
		return fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa", parts[3], parts[2], parts[1], parts[0])
	}
	
	// IPv6 reverse DNS is more complex
	expandedIPv6 := expandIPv6(ip.value)
	chars := strings.ReplaceAll(expandedIPv6, ":", "")
	
	var reverse strings.Builder
	for i := len(chars) - 1; i >= 0; i-- {
		reverse.WriteByte(chars[i])
		if i > 0 {
			reverse.WriteByte('.')
		}
	}
	reverse.WriteString(".ip6.arpa")
	
	return reverse.String()
}

// GetAddressClass returns the class of IPv4 address (A, B, C, D, E)
func (ip IPAddress) GetAddressClass() string {
	if !ip.IsIPv4() {
		return ""
	}
	
	parts := strings.Split(ip.value, ".")
	if len(parts) != 4 {
		return ""
	}
	
	firstOctet, err := strconv.Atoi(parts[0])
	if err != nil {
		return ""
	}
	
	if firstOctet >= 1 && firstOctet <= 126 {
		return "A"
	} else if firstOctet >= 128 && firstOctet <= 191 {
		return "B"
	} else if firstOctet >= 192 && firstOctet <= 223 {
		return "C"
	} else if firstOctet >= 224 && firstOctet <= 239 {
		return "D" // Multicast
	} else if firstOctet >= 240 && firstOctet <= 255 {
		return "E" // Reserved
	}
	
	return "Unknown"
}

// IsReserved checks if the address is in a reserved range
func (ip IPAddress) IsReserved() bool {
	if ip.IsIPv4() {
		// Check for reserved IPv4 ranges
		reservedRanges := []string{
			"0.0.0.0/8",        // This network
			"224.0.0.0/4",      // Multicast
			"240.0.0.0/4",      // Reserved for future use
			"255.255.255.255/32", // Broadcast
		}
		
		for _, cidr := range reservedRanges {
			if inRange, _ := ip.IsInRange(cidr); inRange {
				return true
			}
		}
	} else {
		// Check for reserved IPv6 ranges
		reservedRanges := []string{
			"::/128",        // Unspecified
			"::ffff:0:0/96", // IPv4-mapped
			"2001:db8::/32", // Documentation
			"ff00::/8",      // Multicast
		}
		
		for _, cidr := range reservedRanges {
			if inRange, _ := ip.IsInRange(cidr); inRange {
				return true
			}
		}
	}
	
	return false
}

// GetInfo returns detailed information about the IP address
func (ip IPAddress) GetInfo() map[string]interface{} {
	info := map[string]interface{}{
		"address":     ip.value,
		"type":        string(ip.ipType),
		"is_private":  ip.isPrivate,
		"is_public":   ip.IsPublic(),
		"is_loopback": ip.isLoopback,
		"is_multicast": ip.isMulticast,
		"is_reserved": ip.IsReserved(),
		"reverse_dns": ip.Reverse(),
	}
	
	if ip.IsIPv4() {
		info["class"] = ip.GetAddressClass()
	}
	
	return info
}

// ToBytes returns the IP address as a byte slice
func (ip IPAddress) ToBytes() []byte {
	if ip.network == nil {
		return nil
	}
	
	if ip.IsIPv4() {
		return ip.network.To4()
	}
	
	return ip.network.To16()
}

// isPrivateIP checks if an IP address is in a private range
func isPrivateIP(ip net.IP) bool {
	if ip.To4() != nil {
		// IPv4
		for _, privateRange := range privateIPv4Ranges {
			if privateRange.Contains(ip) {
				return true
			}
		}
	} else {
		// IPv6
		for _, privateRange := range privateIPv6Ranges {
			if privateRange.Contains(ip) {
				return true
			}
		}
	}
	
	return false
}

// expandIPv6 expands an IPv6 address to its full form
func expandIPv6(address string) string {
	ip := net.ParseIP(address)
	if ip == nil {
		return ""
	}
	
	if ip.To4() != nil {
		return "" // Not IPv6
	}
	
	// Convert to 16-byte representation and format
	ipv6 := ip.To16()
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ipv6[0], ipv6[1], ipv6[2], ipv6[3],
		ipv6[4], ipv6[5], ipv6[6], ipv6[7],
		ipv6[8], ipv6[9], ipv6[10], ipv6[11],
		ipv6[12], ipv6[13], ipv6[14], ipv6[15])
}

// ValidateIPRange validates a CIDR range
func ValidateIPRange(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	return err
}

// ParseIPRange parses a CIDR range and returns network information
func ParseIPRange(cidr string) (network, broadcast IPAddress, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return IPAddress{}, IPAddress{}, err
	}
	
	// Network address
	networkAddr, err := NewIPAddress(ipNet.IP.String())
	if err != nil {
		return IPAddress{}, IPAddress{}, err
	}
	
	// Calculate broadcast address for IPv4
	if ip.To4() != nil {
		broadcast := make(net.IP, len(ipNet.IP))
		copy(broadcast, ipNet.IP)
		
		// Set host bits to 1
		for i := range broadcast {
			broadcast[i] |= ^ipNet.Mask[i]
		}
		
		broadcastAddr, err := NewIPAddress(broadcast.String())
		if err != nil {
			return IPAddress{}, IPAddress{}, err
		}
		
		return networkAddr, broadcastAddr, nil
	}
	
	// For IPv6, there's no broadcast concept
	return networkAddr, IPAddress{}, nil
}

// IsValidIPOrCIDR checks if a string is a valid IP address or CIDR range
func IsValidIPOrCIDR(input string) bool {
	// Try parsing as IP address
	if _, err := NewIPAddress(input); err == nil {
		return true
	}
	
	// Try parsing as CIDR
	_, _, err := net.ParseCIDR(input)
	return err == nil
}

// GetIPsInRange returns all IP addresses in a given IPv4 CIDR range (up to /24)
func GetIPsInRange(cidr string) ([]IPAddress, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	
	// Only support IPv4 and limit to reasonable ranges
	if ip.To4() == nil {
		return nil, errors.New("IPv6 ranges not supported")
	}
	
	ones, _ := ipNet.Mask.Size()
	if ones < 24 {
		return nil, errors.New("range too large (maximum /24 supported)")
	}
	
	var ips []IPAddress
	
	// Calculate all IPs in range
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		addr, err := NewIPAddress(ip.String())
		if err != nil {
			continue
		}
		ips = append(ips, addr)
	}
	
	return ips, nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// CompareIPAddresses compares two IP addresses for sorting
func CompareIPAddresses(ip1, ip2 IPAddress) int {
	// Convert to bytes for comparison
	bytes1 := ip1.ToBytes()
	bytes2 := ip2.ToBytes()
	
	// Compare byte by byte
	minLen := len(bytes1)
	if len(bytes2) < minLen {
		minLen = len(bytes2)
	}
	
	for i := 0; i < minLen; i++ {
		if bytes1[i] < bytes2[i] {
			return -1
		} else if bytes1[i] > bytes2[i] {
			return 1
		}
	}
	
	// If all compared bytes are equal, shorter address comes first
	if len(bytes1) < len(bytes2) {
		return -1
	} else if len(bytes1) > len(bytes2) {
		return 1
	}
	
	return 0
}

// ValidatePortWithIP validates a port number for the given IP context
func ValidatePortWithIP(ip IPAddress, port int) error {
	if port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	
	// Additional validation based on IP type if needed
	// This is a placeholder for future enhancements
	
	return nil
}