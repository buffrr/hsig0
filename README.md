# HSig0

Go library to validate dns messages using Handshake sig0. You can use it to resolve names over the handshake network and verify them using the node's public key. 

## Usage

~~~Go
package main

import (
	"fmt"
	"github.com/buffrr/hsig0"
	"github.com/miekg/dns"
	"log"
)

func main() {
	k, err := hsig0.ParsePublicKey("aj7bjss4ae6hd3kdxzl4f6klirzla377uifxu5mnzczzk2v7p76ek")
	if err != nil {
		log.Fatal(err)
	}

	// basic dns query
	client := new(dns.Client)
	query := new(dns.Msg)
	query.SetQuestion("proofofconcept.", dns.TypeA)

	msg, _, err := client.Exchange(query, "192.168.1.21:8181") // node ip:port
	if err != nil {
		log.Fatal(err)
	}

	if err := hsig0.Verify(msg, k) ; err != nil {
		log.Fatal(err)
	}

	fmt.Println("Success ✔️")
	fmt.Println(msg)
}
~~~



## Other languages

* Javascript: https://github.com/handshake-org/hdns
* C: https://github.com/handshake-org/libhns


## License

MIT