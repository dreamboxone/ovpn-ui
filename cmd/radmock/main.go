// radmock — a logging mock RADIUS server. It answers every Access-Request with
// Access-Accept + a Framed-IP-Address, and DUMPS every attribute of the incoming
// request. Point ocserv's radcli at it to see exactly what ocserv puts on the wire
// (PAP User-Password vs CHAP-Password, the User-Name, the NAS-Identifier, etc.).
package main

import (
	"fmt"
	"net"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func main() {
	secret := []byte("testsecret")
	h := func(w radius.ResponseWriter, r *radius.Request) {
		fmt.Printf("\n[radmock] === %v from %v ===\n", r.Code, r.RemoteAddr)
		user := rfc2865.UserName_GetString(r.Packet)
		nas := rfc2865.NASIdentifier_GetString(r.Packet)
		pw := rfc2865.UserPassword_GetString(r.Packet) // decoded with `secret`
		fmt.Printf("[radmock] User-Name=%q  NAS-Identifier=%q\n", user, nas)
		fmt.Printf("[radmock] User-Password(PAP, decoded)=%q\n", pw)

		// Which auth attributes are present tells us PAP vs CHAP vs MS-CHAP.
		hasUserPass := r.Packet.Get(radius.Type(2)) != nil  // User-Password (PAP)
		hasChapPass := r.Packet.Get(radius.Type(3)) != nil  // CHAP-Password
		hasChapChal := r.Packet.Get(radius.Type(60)) != nil // CHAP-Challenge
		fmt.Printf("[radmock] PAP?=%v  CHAP-Password?=%v  CHAP-Challenge?=%v\n", hasUserPass, hasChapPass, hasChapChal)

		// Full raw dump of every attribute type present.
		fmt.Printf("[radmock] all attributes:\n")
		for t := 1; t <= 255; t++ {
			if v := r.Packet.Get(radius.Type(t)); v != nil {
				fmt.Printf("    type %3d  len %2d  hex=%x  str=%q\n", t, len(v), []byte(v), string(v))
			}
		}

		resp := r.Response(radius.CodeAccessAccept)
		rfc2865.FramedIPAddress_Set(resp, net.ParseIP("10.4.1.2").To4())
		w.Write(resp)
		fmt.Printf("[radmock] -> Access-Accept (Framed-IP 10.4.1.2)\n")
	}
	srv := radius.PacketServer{Addr: "127.0.0.1:1812", Handler: radius.HandlerFunc(h), SecretSource: radius.StaticSecretSource(secret)}
	fmt.Println("[radmock] listening 127.0.0.1:1812 (secret=testsecret)")
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}
