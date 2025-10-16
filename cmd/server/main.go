package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"rt-chat/internal/auth"
	"rt-chat/internal/handlers"
	"rt-chat/internal/hub"
	m "rt-chat/internal/metrics"
	"rt-chat/internal/repository"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	hub := hub.NewHub()
	go hub.Run()

	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Unable to load .env file")
	}

	// Инициализация PostgreSQL (опционально)
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			log.Fatalf("failed to open postgres: %v", err)
		}
		defer db.Close()
		if err := db.Ping(); err != nil {
			log.Fatalf("failed to ping postgres: %v", err)
		}
		userRepo := repository.NewPostgresUserRepository(db)
		if err := userRepo.AutoMigrate(context.Background()); err != nil {
			log.Fatalf("failed to migrate: %v", err)
		}
		auth.SetUserRepository(userRepo)
		log.Println("PostgreSQL users repository enabled")
	} else {
		log.Println("DATABASE_URL not set, using in-memory users store")
	}

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handlers.ServeWebSocket(hub, w, r)
	})

	http.Handle("/", http.FileServer(http.Dir("./static")))

	// Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	// Регистрация нового пользователя
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Проверяем, что это POST запрос
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			m.ObserveHTTPRequest(r.Method, "/register", http.StatusMethodNotAllowed, time.Since(start))
			m.IncRegisterAttempt(false)
			return
		}

		// Парсим JSON из тела запроса
		var registerData struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&registerData); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid JSON"))
			m.ObserveHTTPRequest(r.Method, "/register", http.StatusBadRequest, time.Since(start))
			m.IncRegisterAttempt(false)
			return
		}

		if registerData.Username == "" || registerData.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Username and password are required"))
			m.ObserveHTTPRequest(r.Method, "/register", http.StatusBadRequest, time.Since(start))
			m.IncRegisterAttempt(false)
			return
		}

		// Регистрируем пользователя
		if err := auth.RegisterUser(registerData.Username, registerData.Password); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			m.ObserveHTTPRequest(r.Method, "/register", http.StatusBadRequest, time.Since(start))
			m.IncRegisterAttempt(false)
			return
		}

		// Возвращаем успешный ответ
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "User registered successfully",
		})
		m.ObserveHTTPRequest(r.Method, "/register", http.StatusOK, time.Since(start))
		m.IncRegisterAttempt(true)
	})

	// Логин - устанавливаем куки access и refresh токенов
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			m.ObserveHTTPRequest(r.Method, "/login", http.StatusMethodNotAllowed, time.Since(start))
			m.IncLoginAttempt(false)
			return
		}
		var loginData struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid JSON"))
			m.ObserveHTTPRequest(r.Method, "/login", http.StatusBadRequest, time.Since(start))
			m.IncLoginAttempt(false)
			return
		}
		if loginData.Username == "" || loginData.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Username and password are required"))
			m.ObserveHTTPRequest(r.Method, "/login", http.StatusBadRequest, time.Since(start))
			m.IncLoginAttempt(false)
			return
		}
		user, err := auth.AuthenticateUser(loginData.Username, loginData.Password)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			m.ObserveHTTPRequest(r.Method, "/login", http.StatusUnauthorized, time.Since(start))
			m.IncLoginAttempt(false)
			return
		}
		tokens, err := auth.GenerateTokenPair(user, hub.Repo)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			m.ObserveHTTPRequest(r.Method, "/login", http.StatusInternalServerError, time.Since(start))
			m.IncLoginAttempt(false)
			return
		}
		auth.SetJWTCookie(w, tokens.AccessToken)
		auth.SetRefreshCookie(w, tokens.RefreshToken)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "Login successful",
		})
		m.ObserveHTTPRequest(r.Method, "/login", http.StatusOK, time.Since(start))
		m.IncLoginAttempt(true)
	})

	// Endpoint для обновления access токена по refresh токену
	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		refreshToken, err := auth.GetRefreshCookie(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("No refresh token"))
			return
		}
		user, err := auth.ValidateRefreshToken(refreshToken, hub.Repo)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid refresh token"))
			auth.ClearJWTCookie(w)
			auth.ClearRefreshCookie(w)
			return
		}
		tokens, err := auth.GenerateTokenPair(user, hub.Repo)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Token error"))
			return
		}
		auth.SetJWTCookie(w, tokens.AccessToken)
		auth.SetRefreshCookie(w, tokens.RefreshToken)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "Tokens refreshed",
		})
	})

	// Логаут - удаляем куки и refresh токен
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		refreshToken, _ := auth.GetRefreshCookie(r)
		auth.ClearJWTCookie(w)
		auth.ClearRefreshCookie(w)
		if refreshToken != "" {
			_ = auth.DeleteRefreshToken(refreshToken, hub.Repo)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Logout successful"))
		m.ObserveHTTPRequest(r.Method, "/logout", http.StatusOK, time.Since(start))
	})

	// Проверка авторизации и информация о сессии
	http.HandleFunc("/check-auth", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		token, err := auth.GetJWTCookie(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			m.ObserveHTTPRequest(r.Method, "/check-auth", http.StatusUnauthorized, time.Since(start))
			return
		}

		claims, err := auth.ValidateToken(token)
		if err != nil {
			auth.ClearJWTCookie(w) // Удаляем невалидную куку
			w.WriteHeader(http.StatusUnauthorized)
			m.ObserveHTTPRequest(r.Method, "/check-auth", http.StatusUnauthorized, time.Since(start))
			return
		}

		// Получаем время истечения
		expiry := time.Now().Add(24 * time.Hour) // По умолчанию
		if claims.ExpiresAt != nil {
			expiry = claims.ExpiresAt.Time
		}

		response := map[string]interface{}{
			"username":   claims.Username,
			"expires_at": expiry.Format(time.RFC3339),
			"expires_in": int(time.Until(expiry).Seconds()),
			"status":     "authorized",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		m.ObserveHTTPRequest(r.Method, "/check-auth", http.StatusOK, time.Since(start))
	})

	srv := &http.Server{Addr: "0.0.0.0:8000"}

	go func() {
		log.Println("Server started on :8000")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop

	log.Println("Shutting down...")
	hub.Quit <- struct{}{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("HTTP server Shutdown: %v", err)
	}
	if hub.Repo != nil {
		if err := hub.Repo.Close(); err != nil {
			log.Printf("Error closing Redis: %v", err)
		}
	}
	log.Println("Stopped")
}
