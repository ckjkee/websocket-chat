package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"rt-chat/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	SecretKey = []byte("your-secret-key") // TODO: Change to real one

	// In-memory storage for users (temporary, will be replaced with PostgreSQL)
	users    = make(map[string]*User)
	usersMux sync.RWMutex

	// Optional external user repository (e.g., PostgreSQL). If nil, fallback to in-memory map
	userRepo repository.UserRepository
)

type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"` // Don't expose password hash in JSON
	CreatedAt    time.Time `json:"created_at"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func SetUserRepository(repo repository.UserRepository) {
	userRepo = repo
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func checkPassword(password, hash string) bool {
	return hashPassword(password) == hash
}

func RegisterUser(username, password string) error {
	if len(password) < 6 {
		return errors.New("password must be at least 6 characters long")
	}

	if userRepo != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := userRepo.GetUserByUsername(ctx, username); err == nil {
			return errors.New("user already exists")
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		return userRepo.CreateUser(ctx, username, hashPassword(password))
	}

	// Fallback: in-memory
	usersMux.Lock()
	defer usersMux.Unlock()
	if _, exists := users[username]; exists {
		return errors.New("user already exists")
	}
	users[username] = &User{
		Username:     username,
		PasswordHash: hashPassword(password),
		CreatedAt:    time.Now(),
	}
	return nil
}

func AuthenticateUser(username, password string) (*User, error) {
	if userRepo != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		rec, err := userRepo.GetUserByUsername(ctx, username)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, errors.New("user not found")
			}
			return nil, err
		}
		if !checkPassword(password, rec.PasswordHash) {
			return nil, errors.New("invalid password")
		}
		return &User{Username: rec.Username, PasswordHash: rec.PasswordHash, CreatedAt: rec.CreatedAt}, nil
	}

	// Fallback: in-memory
	usersMux.RLock()
	defer usersMux.RUnlock()
	user, exists := users[username]
	if !exists {
		return nil, errors.New("user not found")
	}
	if !checkPassword(password, user.PasswordHash) {
		return nil, errors.New("invalid password")
	}
	return user, nil
}

func GetUser(username string) (*User, error) {
	if userRepo != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		rec, err := userRepo.GetUserByUsername(ctx, username)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, errors.New("user not found")
			}
			return nil, err
		}
		return &User{Username: rec.Username, PasswordHash: rec.PasswordHash, CreatedAt: rec.CreatedAt}, nil
	}

	// Fallback: in-memory
	usersMux.RLock()
	defer usersMux.RUnlock()
	user, exists := users[username]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func GenerateToken(username string) (string, error) {
	claims := Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(SecretKey)
}

func GenerateTokenForUser(user *User) (string, error) {
	return GenerateToken(user.Username)
}

func ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (any, error) {
		return SecretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func GetTokenExpiry(tokenStr string) (time.Time, error) {
	claims, err := ValidateToken(tokenStr)
	if err != nil {
		return time.Time{}, err
	}

	if claims.ExpiresAt != nil {
		return claims.ExpiresAt.Time, nil
	}

	return time.Time{}, errors.New("token has no expiry time")
}

func SetJWTCookie(w http.ResponseWriter, token string) {
	expiry, err := GetTokenExpiry(token)
	if err != nil {
		expiry = time.Now().Add(24 * time.Hour)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "jwt_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // true для HTTPS
		SameSite: http.SameSiteLaxMode,
		Expires:  expiry,
	})
}

func GetJWTCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("jwt_token")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func ClearJWTCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // true для HTTPS
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(-1 * time.Hour),
	})
}

// --- Refresh Token ---
const RefreshTokenTTL = 7 * 24 * time.Hour // 7 дней

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

func GenerateTokenPair(user *User, repo *repository.RedisRepository) (*TokenPair, error) {
	accessToken, err := GenerateToken(user.Username)
	if err != nil {
		return nil, err
	}
	refreshToken := uuid.NewString()
	if repo != nil {
		ctx := context.Background()
		err := repo.SaveRefreshToken(ctx, user.Username, refreshToken, RefreshTokenTTL)
		if err != nil {
			return nil, err
		}
	}
	return &TokenPair{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func ValidateRefreshToken(token string, repo *repository.RedisRepository) (*User, error) {
	if repo == nil {
		return nil, errors.New("refresh token storage not available")
	}
	ctx := context.Background()
	username, err := repo.GetRefreshToken(ctx, token)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}
	return GetUser(username)
}

func DeleteRefreshToken(token string, repo *repository.RedisRepository) error {
	if repo == nil {
		return nil
	}
	ctx := context.Background()
	return repo.DeleteRefreshToken(ctx, token)
}

func SetRefreshCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // true для HTTPS
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(RefreshTokenTTL),
	})
}

// Получение refresh токена из куки
func GetRefreshCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func ClearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(-1 * time.Hour),
	})
}
