package handlers

import (
	"CodeBin/database"
	"CodeBin/middleware"
	"CodeBin/models"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type AuthAndOwnershipResult struct {
	Email   string
	Snippet models.Snippet
}

func authenticateAndVerifyOwnership(w http.ResponseWriter, r *http.Request, snippetID string) (*AuthAndOwnershipResult, error) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Missing authorization header")
		log.Warn("Missing authorization header")
		return nil, fmt.Errorf("missing authorization header")
	}

	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	_, err := middleware.VerifyToken(tokenString)
	if err != nil {
		log.WithError(err).Warn("Token verification failed")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid token")
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	email, err := GetEmailFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		log.WithError(err).Warn("Failed to get email from token")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid token")
		return nil, fmt.Errorf("failed to get email: %v", err)
	}

	var snippet models.Snippet
	if err := database.DB.Where("id = ?", snippetID).First(&snippet).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "Snippet not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to retrieve snippet", http.StatusInternalServerError)
		}
		return nil, fmt.Errorf("snippet retrieval failed: %v", err)
	}

	var ownership models.SnippetOwnership
	if err := database.DB.Where("snippet_id = ? AND email = ?", snippetID, email).First(&ownership).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "Forbidden - not owner", http.StatusForbidden)
		} else {
			http.Error(w, "Failed to check snippet ownership", http.StatusInternalServerError)
		}
		return nil, fmt.Errorf("ownership verification failed: %v", err)
	}

	return &AuthAndOwnershipResult{
		Email:   email,
		Snippet: snippet,
	}, nil
}

func authenticateUser(w http.ResponseWriter, r *http.Request) (string, error) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Missing authorization header")
		log.Warn("Missing authorization header")
		return "", fmt.Errorf("missing authorization header")
	}

	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	_, err := middleware.VerifyToken(tokenString)
	if err != nil {
		log.WithError(err).Warn("Token verification failed")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid token")
		return "", fmt.Errorf("invalid token: %v", err)
	}

	email, err := GetEmailFromBearer(r.Header.Get("Authorization"))
	if err != nil {
		log.WithError(err).Warn("Failed to get email from token")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid token")
		return "", fmt.Errorf("failed to get email: %v", err)
	}

	return email, nil
}

// @Summary Create Snippet
// @Description Create a new code snippet
// @Tags snippets
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param snippet body models.Snippet true "Snippet data"
// @Success 201 {object} map[string]string "Created snippet URL"
// @Failure 400 {string} string "Invalid request body"
// @Failure 401 {string} string "Unauthorized"
// @Failure 409 {string} string "Snippet with this ID already exists"
// @Failure 500 {string} string "Failed to create snippet"
// @Router /create [post]
func CreateSnippet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Authenticate user
	email, err := authenticateUser(w, r)
	if err != nil {
		return // Error response already written by authenticateUser
	}

	var snippet models.Snippet

	if err := json.NewDecoder(r.Body).Decode(&snippet); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Calculate snippet size in bytes
	snippetSize := CheckSize([]byte(snippet.Code))
	snippet.Size = snippetSize

	// Get user's current storage usage
	var user models.User
	userErr := database.DB.Debug().Where("email = ?", email).First(&user).Error
	if userErr != nil {
		log.WithError(userErr).Error("Database error when finding user")
		// If it's a schema error, delete and recreate the user
		if strings.Contains(userErr.Error(), "type assertion") {
			log.Warn("Schema error detected, recreating user...")
			// Delete the problematic user record
			database.DB.Exec("DELETE FROM users WHERE email = ?", email)
			// Create a new user
			newUser := models.User{
				Email:           email,
				CreatedSnippets: models.UintArray{},
				RegisteredAt:    time.Now(),
				TotalStorage:    0,
			}
			if createErr := database.DB.Create(&newUser).Error; createErr != nil {
				log.WithError(createErr).Error("Error creating new user")
				http.Error(w, "Failed to create user", http.StatusInternalServerError)
				return
			}
			user = newUser
			log.Info("Successfully recreated user")
		} else {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}
	}
	log.WithField("email", email).Info("Successfully found user")

	// Check if adding this snippet would exceed 50KB limit (51,200 bytes)
	const maxStorageBytes = 51200 // 50KB in bytes
	if user.TotalStorage+snippetSize > maxStorageBytes {
		http.Error(w, "You've reached the 50KB limit. Either delete some snippets or edit others or this snippet.", http.StatusRequestEntityTooLarge)
		return
	}

	if err := database.DB.Create(&snippet).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			http.Error(w, "Snippet with this ID already exists", http.StatusConflict)
		} else {
			http.Error(w, "Failed to create snippet", http.StatusInternalServerError)
		}
		return
	}

	// Create snippet ownership record
	ownership := models.SnippetOwnership{
		SnippetID: snippet.ID,
		Email:     email,
	}
	if err := database.DB.Create(&ownership).Error; err != nil {
		// If ownership creation fails, we should also delete the snippet to maintain consistency
		database.DB.Delete(&snippet)
		http.Error(w, "Failed to create snippet ownership", http.StatusInternalServerError)
		return
	}

	// Update user's total storage and add snippet ID to array
	updatedSnippets := append(user.CreatedSnippets, snippet.ID)
	database.DB.Model(&user).Updates(map[string]interface{}{
		"total_storage":    user.TotalStorage + snippetSize,
		"created_snippets": updatedSnippets,
	})

	w.WriteHeader(http.StatusCreated)

	// Create response with snippet URL
	response := map[string]interface{}{
		"url": fmt.Sprintf("localhost:8080/view/%d", snippet.ID),
	}

	json.NewEncoder(w).Encode(response)

}

// @Summary View Snippet
// @Description View a code snippet
// @Tags snippets
// @Accept json
// @Produce json
// @Param id path string true "Snippet ID"
// @Success 200 {object} models.Snippet "Snippet found"
// @Failure 404 {string} string "Snippet not found"
// @Failure 401 {string} string "Unauthorized"
// @Router /view/{id} [get]
func ViewSnippet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var snippet models.Snippet
	// Get snippet ID from URL path
	path := r.URL.Path
	idStr := path[len("/view/"):]

	// Validate ID is a valid uint
	var id uint
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil {
		http.Error(w, "Invalid snippet ID", http.StatusBadRequest)
		log.WithField("snippet_id", idStr).Warn("Invalid snippet ID format")
		return
	}

	log.WithField("snippet_id", id).Info("Looking for snippet")

	if err := database.DB.Debug().Where("id = ?", id).First(&snippet).Error; err != nil {
		log.WithError(err).Warn("Database error when retrieving snippet")
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "Snippet not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to retrieve snippet", http.StatusInternalServerError)
		}
		return
	}
	json.NewEncoder(w).Encode(snippet)
}

// @Summary Delete Snippet
// @Description Delete a code snippet by ID
// @Tags snippets
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Snippet ID"
// @Success 200 {string} string "Snippet deleted successfully"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden - not owner"
// @Failure 404 {string} string "Snippet not found"
// @Failure 500 {string} string "Failed to delete snippet"
// @Router /delete/{id} [delete]
func DeleteSnippet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get snippet ID from URL path
	path := r.URL.Path
	idStr := path[len("/delete/"):]

	// Validate ID is a valid uint
	var id uint
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil {
		http.Error(w, "Invalid snippet ID", http.StatusBadRequest)
		log.WithField("snippet_id", idStr).Warn("Invalid snippet ID format")
		return
	}

	// Authenticate user and verify ownership
	result, err := authenticateAndVerifyOwnership(w, r, idStr)
	if err != nil {
		return // Error response already written by authenticateAndVerifyOwnership
	}

	// Snippet exists and user is owner, proceed to delete
	snippetSize := result.Snippet.Size // Get the size before deletion

	if err := database.DB.Delete(&result.Snippet).Error; err != nil {
		http.Error(w, "Failed to delete snippet", http.StatusInternalServerError)
		return
	}

	// Update user's total storage and remove snippet ID from array
	var user models.User
	if err := database.DB.Where("email = ?", result.Email).First(&user).Error; err == nil {
		// Remove snippet ID from the user's CreatedSnippets array
		updatedSnippets := make(models.UintArray, 0)
		for _, id := range user.CreatedSnippets {
			if id != result.Snippet.ID {
				updatedSnippets = append(updatedSnippets, id)
			}
		}

		database.DB.Model(&user).Updates(map[string]interface{}{
			"total_storage":    user.TotalStorage - snippetSize,
			"created_snippets": updatedSnippets,
		})
	}

	w.WriteHeader(http.StatusOK)
	log.WithFields(log.Fields{"snippet_id": result.Snippet.ID, "email": result.Email}).Info("Snippet deleted successfully")
	json.NewEncoder(w).Encode(map[string]string{"message": "Snippet deleted successfully"})

}

// @Summary Edit Snippet
// @Description Edit a code snippet by ID (partial updates allowed)
// @Tags snippets
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Snippet ID"
// @Param snippet body object true "Partial snippet data to update"
// @Success 200 {object} models.Snippet "Snippet updated successfully"
// @Failure 400 {string} string "Invalid request body"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden - not owner"
// @Failure 404 {string} string "Snippet not found"
// @Failure 500 {string} string "Failed to update snippet"
// @Router /edit/{id} [put]
func EditSnippet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get snippet ID from URL path (fix the path parsing)
	path := r.URL.Path
	idStr := path[len("/edit/"):]

	// Validate ID is a valid uint
	var id uint
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil {
		http.Error(w, "Invalid snippet ID", http.StatusBadRequest)
		log.WithField("snippet_id", idStr).Warn("Invalid snippet ID format")
		return
	}

	// Authenticate user and verify ownership
	result, err := authenticateAndVerifyOwnership(w, r, idStr)
	if err != nil {
		return // Error response already written by authenticateAndVerifyOwnership
	}

	// Parse the request body for partial updates
	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Create updates map for GORM
	updates := make(map[string]interface{})
	var newCodeSize int64
	var oldCodeSize = result.Snippet.Size

	// Only update fields that are provided in the request
	if name, exists := updateData["name"]; exists {
		updates["name"] = name
	}
	if description, exists := updateData["description"]; exists {
		updates["description"] = description
	}
	if code, exists := updateData["code"]; exists {
		codeStr := code.(string)
		newCodeSize = CheckSize([]byte(codeStr))

		// Check storage limit if code is being updated
		var user models.User
		if err := database.DB.Where("email = ?", result.Email).First(&user).Error; err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

		// Calculate storage difference
		sizeDiff := newCodeSize - oldCodeSize
		if user.TotalStorage+sizeDiff > 51200 { // 50KB limit in bytes
			http.Error(w, "You've reached the 50KB limit. Either delete some snippets or edit others or this snippet.", http.StatusRequestEntityTooLarge)
			return
		}

		updates["code"] = codeStr
		updates["size"] = newCodeSize
	}
	if language, exists := updateData["language"]; exists {
		updates["language"] = language
	}

	// If no valid fields to update, return error
	if len(updates) == 0 {
		http.Error(w, "No valid fields to update", http.StatusBadRequest)
		return
	}

	// Update the snippet with only the provided fields
	if err := database.DB.Model(&result.Snippet).Updates(updates).Error; err != nil {
		http.Error(w, "Failed to update snippet", http.StatusInternalServerError)
		return
	}

	// Update user's total storage if code was changed
	if _, codeUpdated := updateData["code"]; codeUpdated {
		var user models.User
		if err := database.DB.Where("email = ?", result.Email).First(&user).Error; err == nil {
			sizeDiff := newCodeSize - oldCodeSize
			database.DB.Model(&user).Update("total_storage", user.TotalStorage+sizeDiff)
		}
	}

	// Fetch the updated snippet to return
	var updatedSnippet models.Snippet
	if err := database.DB.Where("id = ?", id).First(&updatedSnippet).Error; err != nil {
		http.Error(w, "Failed to retrieve updated snippet", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(updatedSnippet)
}

func CheckSize(input []byte) int64 {
	return int64(len(input)) // Return size in bytes for accuracy
}
