package wireless

import "fmt"

// AccessMethod is how a station gained network access: the combination of
// the SSID's link security (AKM) and the user authentication on top of it.
// It is what an operator asks first when a user "cannot get online".
type AccessMethod uint8

// Access methods. AccessUnknown means the evidence did not decide it.
const (
	AccessUnknown AccessMethod = iota
	// AccessDot1X is 802.1X/EAP with per-user credentials (WPA2/3-Enterprise).
	AccessDot1X
	// AccessPSKMAC is a pre-shared key plus RADIUS MAC authentication (MAB).
	AccessPSKMAC
	// AccessPSK is a pre-shared key only; the controller bypasses user
	// authentication and anyone with the key is admitted.
	AccessPSK
	// AccessMAC is MAC authentication on an open SSID.
	AccessMAC
	// AccessPortal is web portal authentication on an open SSID.
	AccessPortal
	// AccessMACPortal is MAC-trigger portal: a known MAC is admitted
	// silently, an unknown one is redirected to the portal.
	AccessMACPortal
	// AccessOpen is an open SSID with no authentication at all.
	AccessOpen
)

var accessNames = [...]string{
	AccessUnknown:   "",
	AccessDot1X:     "802.1X",
	AccessPSKMAC:    "PSK+MAC",
	AccessPSK:       "PSK",
	AccessMAC:       "MAC",
	AccessPortal:    "Portal",
	AccessMACPortal: "MAC+Portal",
	AccessOpen:      "Open",
}

// String returns the operator-facing label.
func (a AccessMethod) String() string {
	if a.Valid() {
		return accessNames[a]
	}
	return fmt.Sprintf("AccessMethod(%d)", uint8(a))
}

// Valid reports whether a is a declared method, including AccessUnknown.
func (a AccessMethod) Valid() bool { return int(a) < len(accessNames) }

// Authenticated reports whether the method verifies the individual user or
// device against an authentication server, as opposed to a shared key or
// nothing.
func (a AccessMethod) Authenticated() bool {
	switch a {
	case AccessDot1X, AccessPSKMAC, AccessMAC, AccessPortal, AccessMACPortal:
		return true
	case AccessUnknown, AccessPSK, AccessOpen:
		return false
	}
	return false
}

// MarshalText encodes a as its label.
func (a AccessMethod) MarshalText() ([]byte, error) {
	if !a.Valid() {
		return nil, fmt.Errorf("wireless: invalid access method %d", uint8(a))
	}
	return []byte(a.String()), nil
}

// UnmarshalText decodes a label produced by MarshalText.
func (a *AccessMethod) UnmarshalText(text []byte) error {
	for i, name := range accessNames {
		if name == string(text) {
			*a = AccessMethod(i)
			return nil
		}
	}
	return fmt.Errorf("wireless: unknown access method %q", text)
}

// AuthKind is the authenticator that owns an [AuthSession].
type AuthKind string

// Authenticators.
const (
	AuthDot1X AuthKind = "dot1x"
	AuthMAC   AuthKind = "mac"
)

// Valid reports whether k is a declared authenticator.
func (k AuthKind) Valid() bool { return k == AuthDot1X || k == AuthMAC }

// String returns the operator-facing label.
func (k AuthKind) String() string {
	switch k {
	case AuthDot1X:
		return "802.1X"
	case AuthMAC:
		return "MAC"
	}
	return string(k)
}
