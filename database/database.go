package database

import (
	"CodeBin/models"

	"github.com/glebarez/sqlite"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Initialize() {
	var err error
	DB, err = gorm.Open(sqlite.Open("codebin.db"), &gorm.Config{})
	if err != nil {
		log.Errorf("Failed to connect to database!: %v\n", err)
		panic("Failed to connect to database!")
	}

	log.Info("Migrating database schema...")
	err = DB.AutoMigrate(&models.Snippet{}, &models.EmailAuth{}, &models.User{}, &models.SnippetOwnership{})
	if err != nil {
		log.Errorf("Migration error: %v\n", err)
	} else {
		log.Info("Database migration completed successfully")
	}
}
