package ds

import (
	"fmt"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email              string `gorm:"uniqueIndex;not null"`
	Username           string `gorm:"uniqueIndex;not null"`
	PasswordBcryptHash []byte `gorm:"not null"`
	IsVerified         bool   `gorm:"default:false"`
}

type TokenData struct {
	gorm.Model
	AssociatedUserID uint      // Foreign key for User
	AssociatedUser   User      `gorm:"foreignKey:AssociatedUserID"` // The user who made the token
	Generated        time.Time `gorm:"not null"`                    // when they made the token
	Token            string    `gorm:"uniqueIndex;not null"`        // The token
	Disabled         bool      `gorm:"default:false"`               // when true, it's blacklisted
}

type UserMeta struct {
	gorm.Model
	UserID   uint `gorm:"uniqueIndex"`       // Foreign key for User
	UserData User `gorm:"foreignKey:UserID"` // foreign ref to User struct
}

// SetupNewDatabase creates a new database and runs migrations
func SetupNewDatabase(dbPath string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	// Run migrations
	err = db.AutoMigrate(&User{}, &TokenData{}, &UserMeta{})
	if err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return db, nil
}

// LoadExistingDatabase opens an existing database and runs migrations
func LoadExistingDatabase(dbPath string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Run migrations (this will add any new fields/tables)
	err = db.AutoMigrate(&User{}, &TokenData{}, &UserMeta{})
	if err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return db, nil
}
