package repository

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisRepository struct {
	client *redis.Client
}

func NewRedisRepository() (*RedisRepository, error) {
	db, _ := strconv.Atoi(os.Getenv("REDIS_DB"))
	client := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       db,
	})

	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}

	return &RedisRepository{client: client}, nil
}

func (r *RedisRepository) SaveMessage(ctx context.Context, room string, message string) error {
	return r.client.LPush(ctx, "chat:"+room, message).Err()
}

func (r *RedisRepository) GetMessages(ctx context.Context, room string) ([]string, error) {
	return r.client.LRange(ctx, "chat:"+room, 0, 49).Result()
}

func (r *RedisRepository) SaveRefreshToken(ctx context.Context, username, token string, expiresIn time.Duration) error {
	return r.client.Set(ctx, "refresh:"+token, username, expiresIn).Err()
}

func (r *RedisRepository) GetRefreshToken(ctx context.Context, token string) (string, error) {
	return r.client.Get(ctx, "refresh:"+token).Result()
}

func (r *RedisRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	return r.client.Del(ctx, "refresh:"+token).Err()
}

func (r *RedisRepository) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}
