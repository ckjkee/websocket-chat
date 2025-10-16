package client

import (
	"log"
	"net/http"
	"rt-chat/internal/hub"
	m "rt-chat/internal/metrics"

	"github.com/gorilla/websocket"
)

var Upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Client struct {
	Hub      *hub.Hub
	Conn     *websocket.Conn
	Send     chan []byte
	Username string
}

func (c *Client) GetSend() chan []byte {
	return c.Send
}

func (c *Client) GetName() string {
	return c.Username
}

func (c *Client) CloseConn() {
	_ = c.Conn.Close()
}

func (c *Client) Read() {
	defer func() {
		c.Hub.Unregister <- c
		c.Conn.Close()
	}()

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			log.Println("Read error", err)
			m.IncWSReadError()
			break
		}
		m.ObserveMessageSize(len(message))
		c.Hub.BroadcastMessage(c, message)
	}
}

func (c *Client) Write() {
	defer func() {
		c.Conn.Close()
	}()

	for message := range c.Send {
		if err := c.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
			log.Println("Write error:", err)
			m.IncWSWriteError()
			break
		}
	}
}
