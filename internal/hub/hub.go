package hub // Менеджер подключений
import (
	"context"
	"fmt"
	"log"
	"rt-chat/internal/repository"
	"time"

	m "rt-chat/internal/metrics"
)

type Client interface {
	GetSend() chan []byte
	GetName() string
	CloseConn()
}

type Hub struct {
	Clients    map[Client]bool
	Broadcast  chan []byte
	Register   chan Client
	Unregister chan Client
	Repo       *repository.RedisRepository
	Quit       chan struct{}
}

func NewHub() *Hub {
	repo, err := repository.NewRedisRepository()
	if err != nil {
		log.Println("Redis not available:", err)
	} else {
		log.Println("Connected to Redis")
	}

	return &Hub{
		Clients:    make(map[Client]bool),
		Broadcast:  make(chan []byte),
		Register:   make(chan Client),
		Unregister: make(chan Client),
		Repo:       repo,
		Quit:       make(chan struct{}),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			h.Clients[client] = true
			m.IncWSConnections()
		case client := <-h.Unregister:
			if _, ok := h.Clients[client]; ok {
				delete(h.Clients, client)
				close(client.GetSend())
				m.DecWSConnections()
			}
		case message := <-h.Broadcast:
			for client := range h.Clients {
				select {
				case client.GetSend() <- message:
				default:
					close(client.GetSend())
					delete(h.Clients, client)
				}
			}
		case <-h.Quit:
			// Graceful shutdown: close all clients and drain
			for client := range h.Clients {
				close(client.GetSend())
				client.CloseConn()
				delete(h.Clients, client)
				m.DecWSConnections()
			}
			return
		}
	}
}

func (h *Hub) BroadcastMessage(sender Client, message []byte) {
	msg := fmt.Sprintf("[%s] %s: %s", time.Now().Format("15:04:05"), sender.GetName(), string(message))
	if h.Repo != nil {
		ctx := context.Background()
		if err := h.Repo.SaveMessage(ctx, "general", msg); err != nil {
			m.IncRedisError()
		}
	}
	m.IncMessagesBroadcast()
	for client := range h.Clients {
		select {
		case client.GetSend() <- []byte(msg):
		default:
			close(client.GetSend())
			delete(h.Clients, client)
		}
	}
}
