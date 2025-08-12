package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
)

type UintArray []uint

func (ua UintArray) Value() (driver.Value, error) {
	if len(ua) == 0 {
		return "[]", nil
	}
	return json.Marshal(ua)
}

func (ua *UintArray) Scan(value interface{}) error {
	if value == nil {
		*ua = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, ua)
}

type Snippet struct {
	gorm.Model
	Name        string
	Description string
	Code        string `gorm:"type:text"`
	Language    string
	Size        int64 `gorm:"default:0"`
}

type SnippetOwnership struct {
	SnippetID uint   `json:"snippet_id"`
	Email     string `json:"email"`
}

type TestRequest struct {
	Name string `json:"name"`
}

type User struct {
	gorm.Model
	Email           string    `json:"email"`
	CreatedSnippets UintArray `json:"created_snippets" gorm:"type:text"`
	RegisteredAt    time.Time `json:"registered_at"`
	TotalStorage    int64     `json:"total_storage"`
}

func (u *User) GetSnippetCount() int {
	return len(u.CreatedSnippets)
}

func (u *User) HasSnippet(snippetID uint) bool {
	for _, id := range u.CreatedSnippets {
		if id == snippetID {
			return true
		}
	}
	return false
}

type EmailAuth struct {
	Email     string    `gorm:"primaryKey;uniqueIndex" json:"email"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}
