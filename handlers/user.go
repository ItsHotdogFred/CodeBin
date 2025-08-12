package handlers

import (
	"CodeBin/database"
	"CodeBin/models"
	"encoding/json"
	"errors"
	"net/http"

	log "github.com/sirupsen/logrus" // For logging
	"gorm.io/gorm"
)

// @Summary Get User Information
// @Description Get information about the authenticated user
// @Tags user
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.User "User information"
// @Failure 401 {string} string "Unauthorized"
// @Failure 404 {string} string "User not found"
// @Failure 500 {string} string "Internal server error"
// @Router /about [get]
func AboutMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get user email from token
	email, err := GetEmailFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Fetch user information from database
	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			log.Errorf("Failed to retrieve user: %v", err)
			http.Error(w, "Failed to retrieve user", http.StatusInternalServerError)
		}
		return
	}

	// Respond with user information
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Errorf("Failed to encode user response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
