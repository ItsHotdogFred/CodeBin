package middleware

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus" // For logging
)

var SecretKey []byte

func init() {
	// Load .env file before accessing JWT_SECRET
	_ = godotenv.Load()
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		now := time.Now().Format(time.RFC3339)
		hostname, _ := os.Hostname()
		log.WithFields(log.Fields{
			"timestamp": now,
			"hostname":  hostname,
		}).Fatal("JWT_SECRET environment variable not set")
		os.Exit(1)
	}
	SecretKey = []byte(secret)
}

func CreateToken(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"email": email,                                      // Changed from username to email
			"exp":   time.Now().Add(time.Hour * 24 * 30).Unix(), // 30 days
		})
	tokenString, err := token.SignedString(SecretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}
	return tokenString, nil
}

func VerifyToken(tokenString string) (string, error) { // Return email
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return SecretKey, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT token: %w", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}
	email, ok := claims["email"].(string)
	if !ok {
		return "", fmt.Errorf("invalid email in token")
	}
	return email, nil
}
