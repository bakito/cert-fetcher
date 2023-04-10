package server

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"log"
	"net"

	"github.com/bakito/cert-fetcher/cert/selfsigned"
)

func Serve(port int) error {
	cert, err := selfsigned.New()
	if err != nil {
		return fmt.Errorf("server: loadkeys: %w", err)
	}

	// #nosec G402
	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
	}

	config.Rand = rand.Reader
	service := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		return fmt.Errorf("server: listen: %w", err)
	}
	log.Printf("server: listening on port %d", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %v", err)
			break
		}
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go handleClient(conn)
	}
	return nil
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	tlscon, ok := conn.(*tls.Conn)
	if ok {
		log.Print("server: conn: type assert to TLS succeedded")
		err := tlscon.Handshake()
		if err != nil {
			log.Fatalf("server: handshake failed: %v", err)
		}

		log.Print("server: conn: Handshake completed")

		state := tlscon.ConnectionState()
		log.Println("Server: client public key is:")
		for _, v := range state.PeerCertificates {
			var pemBytes bytes.Buffer
			err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: v.Raw})
			if err != nil {
				log.Printf("server: conn: cert could not be read: %v", err)
				break
			}
			fmt.Println(pemBytes.String(), err)
		}
		buf := make([]byte, 512)
		for {
			log.Print("server: conn: waiting")
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("server: conn: read: %v", err)
				break
			}
			log.Printf("server: conn: echo %q\n", string(buf[:n]))
			n, err = conn.Write(buf[:n])
			log.Printf("server: conn: wrote %d bytes", n)
			if err != nil {
				log.Printf("server: write: %s", err)
				break
			}
		}
	}
	log.Println("server: conn: closed")
}
