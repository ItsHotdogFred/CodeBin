package handlers

import (
	"CodeBin/database"
	"CodeBin/middleware"
	"CodeBin/models"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type EmailRequest struct {
	Email string `json:"email"`
}

type TokenVerifyRequest struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type AuthResponse struct {
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

func isValidToken(token string) bool {
	return len(token) == 6
}

func GetEmailFromBearer(authHeader string) (string, error) {
	if authHeader == "" {
		log.Error("missing authorization header")
		return "", errors.New("missing authorization header")
	}

	tokenString := authHeader
	if len(authHeader) > 7 && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = authHeader[7:]
	}

	email, err := middleware.VerifyToken(tokenString)
	if err != nil {
		log.Errorf("invalid token: %v", err)
		return "", errors.New("invalid token")
	}

	return email, nil
}

// @Summary Request Email Token
// @Description User enters email to receive a verification token
// @Tags auth
// @Accept json
// @Produce json
// @Param email body EmailRequest true "Email address"
// @Success 200 {object} AuthResponse "Token sent successfully"
// @Failure 400 {string} string "Invalid request"
// @Failure 500 {string} string "Internal server error"
// @Router /request-token [post]
func RequestToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req EmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	if req.Email == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Email is required"})
		return
	}

	err := middleware.GenerateAndSendToken(req.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to send token: " + err.Error()})
		return
	}

	response := AuthResponse{
		Message: "Token sent to your email",
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// @Summary Verify Email Token
// @Description User verifies email with token to sign in/up
// @Tags auth
// @Accept json
// @Produce json
// @Param verification body TokenVerifyRequest true "Email and token"
// @Success 200 {object} AuthResponse "Successfully authenticated"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Invalid token"
// @Failure 500 {string} string "Internal server error"
// @Router /verify-token [post]
func VerifyToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req TokenVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	if req.Email == "" || req.Token == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Email and token are required"})
		return
	}
	if !isValidToken(req.Token) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token format"})
		return
	}

	// Verify the email token
	err := middleware.VerifyEmailToken(req.Email, req.Token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Clean up the email token after successful verification
	middleware.CleanupEmailToken(req.Email)

	// Create session token (JWT)
	sessionToken, err := middleware.CreateSessionToken(req.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create session"})
		return
	}

	response := AuthResponse{
		Message: "Successfully authenticated",
		Token:   sessionToken,
	}

	NewUser := models.User{
		Email:           req.Email,
		CreatedSnippets: models.UintArray{},
		RegisteredAt:    time.Now(),
		TotalStorage:    0,
	}

	log.Infof("Finding or creating user for email: %s", req.Email)
	result := database.DB.Where("email = ?", req.Email).FirstOrCreate(&NewUser)
	if result.Error != nil {
		log.Errorf("Error creating/finding user: %v", result.Error)
		// If there's still a schema issue, force delete and recreate
		if strings.Contains(result.Error.Error(), "type assertion") {
			log.Warn("Schema mismatch detected, recreating user record")
			// Delete the problematic user record using raw SQL
			database.DB.Exec("DELETE FROM users WHERE email = ?", req.Email)
			// Create a new user
			err = database.DB.Create(&NewUser).Error
			if err != nil {
				log.Errorf("Error creating new user after cleanup: %v", err)
			} else {
				log.Info("Successfully created new user record")
			}
		}
	} else {
		log.Infof("User operation successful. RowsAffected: %d", result.RowsAffected)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
