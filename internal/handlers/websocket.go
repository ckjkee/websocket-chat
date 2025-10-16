package handlers

import (
	"context"
	"log"
	"net/http"
	"rt-chat/internal/auth"
	"rt-chat/internal/client"
	"rt-chat/internal/hub"
	m "rt-chat/internal/metrics"
)

func ServeWebSocket(hub *hub.Hub, w http.ResponseWriter, r *http.Request) {
	// Получаем токен из куки вместо query параметра
	tokenStr, err := auth.GetJWTCookie(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		m.IncWSAuthFailure()
		return
	}

	claims, err := auth.ValidateToken(tokenStr)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		m.IncWSAuthFailure()
		return
	}

	conn, err := client.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		m.IncWSUpgradeError()
		return
	}

	client := &client.Client{
		Hub:      hub,
		Conn:     conn,
		Send:     make(chan []byte, 256),
		Username: claims.Username,
	}

	client.Hub.Register <- client

	// Load last messages from Redis, if repository is configured
	if hub.Repo != nil {
		ctx := context.Background()
		messages, err := hub.Repo.GetMessages(ctx, "general")
		if err != nil {
			log.Println("Redis error:", err)
		} else {
			go func() {
				for _, msg := range messages {
					client.GetSend() <- []byte("[HISTORY]" + msg)
				}
			}()
		}
	}

	go client.Write()
	go client.Read()
}
