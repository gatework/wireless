package h3c

import "github.com/gatework/netops/parse"

// Label tables map Comware labels to canonical fields. Several labels for
// one field cover the spellings of different releases (R5474–R5814).
var (
	clientLabels = parse.Labels{
		"mac":       {"MAC address"},
		"ipv4":      {"IPv4 address"},
		"ipv6":      {"IPv6 address"},
		"username":  {"Username"},
		"ap_id":     {"AP ID"},
		"ap_name":   {"AP name"},
		"radio":     {"Radio ID"},
		"channel":   {"Channel"},
		"ssid":      {"SSID"},
		"bssid":     {"BSSID"},
		"vlan":      {"VLAN ID"},
		"mode":      {"Wireless mode"},
		"bandwidth": {"Channel bandwidth"},
		"rssi":      {"RSSI"},
		"rate":      {"Rx/Tx rate"},
		"speed":     {"Speed"},
		"akm":       {"AKM mode"},
		"user_auth": {"User authentication mode"},
		"cipher":    {"Cipher suite"},
		"security":  {"Security mode"},
		"roam":      {"Roam status"},
		"online":    {"Online time"},
		"sleep":     {"Sleep count"},
	}.MustCompile()

	sessionLabels = parse.Labels{
		"mac":          {"User MAC address"},
		"ap_name":      {"AP name"},
		"radio":        {"Radio ID"},
		"ssid":         {"SSID"},
		"bssid":        {"BSSID"},
		"username":     {"Username"},
		"domain":       {"Authentication domain"},
		"ipv4":         {"IPv4 address"},
		"ipv6":         {"IPv6 address"},
		"method":       {"Authentication method"},
		"initial_vlan": {"Initial VLAN"},
		"auth_vlan":    {"Authorization VLAN"},
		"acl":          {"Authorization ACL number"},
		"profile":      {"Authorization user profile"},
		"since":        {"Online from"},
		"online":       {"Online duration"},
	}.MustCompile()

	bssLabels = parse.Labels{
		"ap_name":   {"AP name"},
		"bssid":     {"BSSID"},
		"radio":     {"Radio ID"},
		"template":  {"Service template name"},
		"ssid":      {"SSID"},
		"vlan":      {"VLAN ID"},
		"akm":       {"AKM mode"},
		"user_auth": {"User authentication mode"},
	}.MustCompile()

	apLabels = parse.Labels{
		"name":        {"AP name"},
		"id":          {"AP ID"},
		"group":       {"AP group name"},
		"state":       {"State"},
		"model":       {"Model"},
		"serial":      {"Serial ID"},
		"mac":         {"MAC address"},
		"ip":          {"IP address"},
		"software":    {"S/W version"},
		"online":      {"Online time"},
		"uptime":      {"System uptime"},
		"reboot":      {"Last reboot reason"},
		"power":       {"Power info"},
		"description": {"Description"},
		"echo":        {"Echo requests"},
		"lost":        {"Lost echo responses"},
	}.MustCompile()

	radioLabels = parse.Labels{
		"bssid":     {"BSSID", "Basic BSSID"},
		"state":     {"State", "Admin state"},
		"type":      {"Type", "Radio type"},
		"channel":   {"Channel"},
		"bandwidth": {"Channel bandwidth"},
		"usage":     {"Channel usage(%)"},
		"power":     {"Max power"},
		"noise":     {"Noise floor"},
	}.MustCompile()
)
