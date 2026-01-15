package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/coder/websocket"
)

type Message struct {
	Type   string `json:"type"`
	Ticket string `json:"ticket,omitempty"`
	User   string `json:"user,omitempty"`
	Path   string `json:"path,omitempty"`
}

type Response struct {
	Type  string `json:"type"`
	Html  string `json:"html,omitempty"`
	Path  string `json:"path,omitempty"`
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

func main() {
	url := flag.String("url", "ws://localhost:8080/ws", "SSR WebSocket URL")
	user := flag.String("user", "glenda", "User to login as")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Printf("Connecting to %s...", *url)
	c, _, err := websocket.Dial(ctx, *url, nil)
	if err != nil {
		log.Fatalf("Dial failed: %v", err)
	}
	defer c.Close(websocket.StatusInternalError, "bye")

	// 2. Protocol: login user=<user>
	log.Printf("Sending Login for %s...", *user)
	if err := c.Write(ctx, websocket.MessageText, []byte(fmt.Sprintf("login user=%s", *user))); err != nil {
		log.Fatal(err)
	}

	// 3. Read Ticket
	// Expect: ticket ticket=<path>
	var ticket string
	{
		typ, data, err := c.Read(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if typ != websocket.MessageText {
			log.Fatal("Expected text message")
		}
		msg := string(data)
		log.Printf("Received: %s", msg)

		if strings.HasPrefix(msg, "ticket ticket=") {
			ticket = strings.TrimPrefix(msg, "ticket ticket=")
		} else {
			log.Fatalf("Expected ticket, got %s", msg)
		}
	}
	log.Printf("Got Ticket: %s", ticket)

	// 4. Protocol: auth user=<user> ticket=<ticket>
	log.Printf("Sending Auth with ticket...")
	authCmd := fmt.Sprintf("auth user=%s ticket=%s", *user, ticket)
	if err := c.Write(ctx, websocket.MessageText, []byte(authCmd)); err != nil {
		log.Fatal(err)
	}

	// 5. Read Render
	// Expect: render path=/ html=<base64>
	{
		typ, data, err := c.Read(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if typ != websocket.MessageText {
			log.Fatal("Expected text message")
		}
		msg := string(data)
		log.Printf("Received Render (len=%d)", len(msg))
		if !strings.HasPrefix(msg, "render path=") {
			log.Fatalf("Expected render, got %s", msg)
		}
	}
	log.Printf("SUCCESS: Auth Flow Complete")
}
