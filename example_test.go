package wireless_test

import (
	"fmt"

	"github.com/gatework/wireless"
)

// Locate a station across controllers by a MAC fragment.
func ExampleIndex_Find() {
	ix := fleet()
	q, _ := wireless.ParseQuery("10-0001")
	for _, v := range ix.Find(q).Clients {
		fmt.Println(v.Controller.Name, v.Client.APName, v.Client.SSID, v.Access)
	}
	// Output:
	// AC-A AP-1 Corp 802.1X
	// AC-B AP-9 Corp
}
