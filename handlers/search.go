package handlers

import (
	"CodeBin/database"
	"CodeBin/models"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	"gorm.io/gorm"
)

// @Summary Search Snippets by Language
// @Description Search for code snippets by programming language
// @Tags snippets
// @Accept json
// @Produce json
// @Param lang path string true "Programming Language" Example(python)
// @Success 200 {array} uint "Snippet IDs found"
// @Failure 400 {string} string "Invalid language parameter"
// @Failure 404 {string} string "No snippets found"
// @Failure 500 {string} string "Failed to retrieve snippets"
// @Router /sl/{lang} [get]
func SearchLanguage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var snippetIDs []uint
	// Get snippet language from URL path
	path := r.URL.Path
	lang := path[len("/sl/"):]

	// Clean up the language string
	lang = strings.TrimSpace(lang)
	lang = strings.Trim(lang, "/") // Remove any trailing slashes
	langLower := strings.ToLower(lang)

	// Case-insensitive search using LOWER in SQL
	db := database.DB.Model(&models.Snippet{}).Where("LOWER(language) = ?", langLower)

	if err := db.Pluck("id", &snippetIDs).Error; err != nil {
		log.WithError(err).Error("Database error when searching for snippets")
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "No snippets found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to retrieve snippets", http.StatusInternalServerError)
		}
		return
	}

	if len(snippetIDs) == 0 {
		log.WithField("language", langLower).Info("No snippets found for language")
		http.Error(w, "No snippets found", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(snippetIDs); err != nil {
		log.WithError(err).Error("Failed to encode snippet IDs response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
