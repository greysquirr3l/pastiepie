package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

var db *gorm.DB
var configLock sync.RWMutex
var config Config

// Config struct to store global settings
type Config struct {
	LogLevel string
	AESKey   string
	DBPath   string
	Port     string
}

// AppConfig struct to store application-wide configurations in the database
type AppConfig struct {
	KeyID           string `gorm:"primary_key"`
	EncryptedAESKey string
}

// Pastie struct to store each pastie
type Pastie struct {
	ID           string `gorm:"primary_key"`
	Content      string
	PasswordHash string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ViewOnce     bool
	Viewed       bool
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("Application panicked: %v", r)
		}
	}()

	log.Println("Starting application...")

	// Initialize configuration
	initConfig()

	// Initialize database
	initDatabase()

	// Verify database is initialized
	if db == nil {
		log.Fatalf("Database initialization failed. Exiting.")
	}
	defer func() {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}()

	// Start cleanup routine for expired pasties
	startExpiredPastiesCleanup(10 * time.Minute)

	// Initialize HTTP server
	r := setupRouter()

	log.Printf("Server starting on port %s", config.Port)
	if err := http.ListenAndServe(":"+config.Port, handlers.CORS(handlers.AllowedOrigins([]string{"*"}))(r)); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func setupRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/", serveCreateForm).Methods("GET")
	r.HandleFunc("/pastie", createPaste).Methods("POST")
	r.HandleFunc("/pastie/{id}", getPaste).Methods("GET", "POST")
	r.HandleFunc("/admin/pasties", adminPasties).Methods("GET")
	r.HandleFunc("/healthz", healthCheck).Methods("GET")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	return r
}

func initConfig() {
	log.Println("Initializing configuration...")

	viper.SetConfigFile("/root/config.yml") // Corrected file extension
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	config.LogLevel = viper.GetString("log_level")
	config.DBPath = viper.GetString("db_path")
	config.Port = viper.GetString("port")

	masterKey := os.Getenv("MASTER_KEY")
	if len(masterKey) != 32 {
		log.Fatalf("MASTER_KEY must be 32 bytes for AES-256 encryption. Current length: %d", len(masterKey))
	}

	// Ensure the database is ready before checking for the AES key
	if db == nil {
		log.Fatalf("Database is not initialized during config setup.")
	}

	var storedKey AppConfig
	result := db.First(&storedKey, "key_id = ?", "aes_key")
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		log.Println("No AES key found, generating a new one...")

		newAESKey := GenerateRandomAESKey()
		encryptedAESKey, err := EncryptAES(newAESKey, masterKey)
		if err != nil {
			log.Fatalf("Failed to encrypt AES key: %v", err)
		}

		storedKey = AppConfig{
			KeyID:           "aes_key",
			EncryptedAESKey: encryptedAESKey,
		}

		if err := db.Create(&storedKey).Error; err != nil {
			log.Fatalf("Failed to store AES key in database: %v", err)
		}

		config.AESKey = newAESKey
		log.Println("Generated and stored new AES key.")
	} else if result.Error != nil {
		log.Fatalf("Failed to query database for AES key: %v", result.Error)
	} else {
		log.Println("AES key found in database. Decrypting...")
		decryptedAESKey, err := DecryptAES(storedKey.EncryptedAESKey, masterKey)
		if err != nil {
			log.Fatalf("Failed to decrypt stored AES key: %v", err)
		}
		config.AESKey = decryptedAESKey
		log.Println("Loaded AES key from database.")
	}

	log.Printf("Configuration loaded: LogLevel=%s, DBPath=%s, Port=%s", config.LogLevel, config.DBPath, config.Port)
}

func generateID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		log.Printf("Failed to generate random ID: %v", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func encrypt(plainText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plainText))
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func decrypt(cipherText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	if len(cipherBytes) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := cipherBytes[:aes.BlockSize]
	cipherBytes = cipherBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherBytes, cipherBytes)
	return string(cipherBytes), nil
}

func GenerateRandomAESKey() string {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate AES key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func EncryptAES(plaintext, masterKey string) (string, error) {
	block, err := aes.NewCipher([]byte(masterKey))
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptAES(ciphertext, masterKey string) (string, error) {
	block, err := aes.NewCipher([]byte(masterKey))
	if err != nil {
		return "", err
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	if len(ciphertextBytes) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertextBytes, ciphertextBytes)
	return string(ciphertextBytes), nil
}
