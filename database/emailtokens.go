package database

import (
	"CodeBin/models"
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
)

func isValidToken(token string) bool {
	return len(token) == 6
}

func SaveEmailToken(ctx context.Context, email, token string) error {
	if !isValidToken(token) {
		err := errors.New("invalid token format")
		return err
	}
	db := DB.WithContext(ctx)

	err := db.Where("email = ?", email).
		Assign(models.EmailAuth{
			Email:     email,
			Token:     token,
			CreatedAt: time.Now(),
		}).
		FirstOrCreate(&models.EmailAuth{}).Error
	if err != nil {
		log.WithFields(log.Fields{
			"email": email,
			"token": token,
		}).WithError(err).Error("Failed to save or update email token")
	}
	return err
}

func GetEmailToken(ctx context.Context, email string) (*models.EmailAuth, error) {
	db := DB.WithContext(ctx)
	var t models.EmailAuth
	err := db.Where("email = ?", email).First(&t).Error
	if err != nil {
		log.WithFields(log.Fields{
			"email": email,
		}).WithError(err).Error("Failed to get email token")
		return nil, err
	}
	return &t, nil
}

func DeleteEmailToken(ctx context.Context, email string) error {
	db := DB.WithContext(ctx)
	err := db.Where("email = ?", email).Delete(&models.EmailAuth{}).Error
	if err != nil {
		log.WithFields(log.Fields{
			"email": email,
		}).WithError(err).Error("Failed to delete email token")
	}
	return err
}
