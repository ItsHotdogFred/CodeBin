package middleware

import (
	"CodeBin/database"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"

	"net/http"
	"os"
	"time"
)

func GenerateAndSendToken(email string) error {
	ctx := context.Background()
	authData, err := database.GetEmailToken(ctx, email)
	if err == nil {
		if time.Since(authData.CreatedAt) < 5*time.Minute {
			log.Warn("Token request too soon")
			return fmt.Errorf("please wait before requesting another token. Try again in a few minutes")
		}
	}

	token, err := generateToken()
	if err != nil {
		log.WithError(err).Error("Failed to generate token")
		return err
	}
	if err := database.SaveEmailToken(ctx, email, token); err != nil {
		log.WithError(err).Error("Failed to save email token")
		return err
	}
	err = sendTokenEmail(email, token)
	if err != nil {
		log.WithError(err).Error("Failed to send token email")
	}
	return err
}

func VerifyEmailToken(email, token string) error {
	ctx := context.Background()
	authData, err := database.GetEmailToken(ctx, email)
	if err != nil {
		log.WithError(err).Warn("No token found for email")
		return fmt.Errorf("no token found for email: %s", email)
	}
	if authData.Token != token {
		log.Warn("Invalid token for email")
		return fmt.Errorf("invalid token for email: %s", email)
	}
	if time.Since(authData.CreatedAt) > 10*time.Minute {
		database.DeleteEmailToken(ctx, email)
		log.Warn("Token expired for email")
		return fmt.Errorf("token expired for email: %s", email)
	}
	return nil
}

func CreateSessionToken(email string) (string, error) {
	return CreateToken(email)
}

func CleanupEmailToken(email string) {
	ctx := context.Background()
	database.DeleteEmailToken(ctx, email)
}

func generateToken() (string, error) {
	bytes := make([]byte, 3)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, 6)
	for i := range token {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		token[i] = charset[int(b[0])%len(charset)]
	}
	return string(token), nil
}

func sendTokenEmail(email, token string) error {
	if email == "" || token == "" {
		log.Warn("Email and token cannot be empty in sendTokenEmail")
		return fmt.Errorf("email and token cannot be empty")
	}

	url := "https://send.api.mailtrap.io/api/send"
	method := "POST"

	subject := "Your CodeBin Access Token"
	body := fmt.Sprintf("Your access token is: %s\n\nThis token will expire in 10 minutes.\n\nIf you didn't request this, someone may be trying to access your account. You can safely ignore this email as they would need access to your email to complete verification.", token)

	fromEmail := os.Getenv("MAILTRAP_EMAIL")
	if fromEmail == "" {
		log.Error("MAILTRAP_EMAIL environment variable not set")
		return fmt.Errorf("MAILTRAP_EMAIL environment variable not set")
	}
	emailData := map[string]interface{}{
		"from": map[string]string{
			"email": fromEmail,
			"name":  "CodeBin",
		},
		"to": []map[string]string{
			{"email": email},
		},
		"subject":  subject,
		"text":     body,
		"category": "Email Verification",
	}

	payloadBytes, err := json.Marshal(emailData)
	if err != nil {
		log.WithError(err).Error("Failed to create JSON payload for email")
		return fmt.Errorf("failed to create JSON payload: %w", err)
	}

	payload := bytes.NewReader(payloadBytes)

	client := &http.Client{}

	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		log.WithError(err).Error("Failed to create HTTP request for email API")
		return fmt.Errorf("failed to create request: %w", err)
	}

	apiToken := os.Getenv("MAILTRAP_API_TOKEN")
	if apiToken == "" {
		log.Error("MAILTRAP_API_TOKEN environment variable not set")
		return fmt.Errorf("MAILTRAP_API_TOKEN environment variable not set")
	}

	req.Header.Add("Authorization", "Bearer "+apiToken)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		log.WithError(err).Error("Failed to send email request to Mailtrap API")
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(res.Body)
		log.WithFields(log.Fields{
			"status":     res.StatusCode,
			"email_hash": hashEmail(email),
		}).Errorf("Email service returned error: %s", string(responseBody))
		return fmt.Errorf("email service returned error status %d", res.StatusCode)
	}

	log.Info("Email sent successfully")

	return nil
}

func hashEmail(email string) string {
	hash := sha256.Sum256([]byte(email))
	return fmt.Sprintf("%x", hash)[:8]
}
