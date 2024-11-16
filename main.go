package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
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

	initConfig()
	initDatabase()
	defer func() {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}()

	// Start cleanup routine for expired pasties
	startExpiredPastiesCleanup(10 * time.Minute)

	// Start the HTTP server
	r := mux.NewRouter()
	r.HandleFunc("/", serveCreateForm).Methods("GET")
	r.HandleFunc("/pastie", createPaste).Methods("POST")
	r.HandleFunc("/pastie/{id}", getPaste).Methods("GET", "POST")
	r.HandleFunc("/admin/pasties", adminPasties).Methods("GET") // Admin page endpoint
	r.HandleFunc("/healthz", healthCheck).Methods("GET")        // Healthcheck endpoint
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	log.Printf("PastiePie server starting on port %s", config.Port)
	if err := http.ListenAndServe(":"+config.Port, handlers.CORS(handlers.AllowedOrigins([]string{"*"}))(r)); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func initConfig() {
	viper.SetConfigFile("/root/config.yml")
	viper.SetConfigType("yml")

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

	var storedKey AppConfig
	result := db.First(&storedKey, "key_id = ?", "aes_key")
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// Generate and store a new AES key
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
		// Decrypt the existing AES key
		decryptedAESKey, err := DecryptAES(storedKey.EncryptedAESKey, masterKey)
		if err != nil {
			log.Fatalf("Failed to decrypt AES key: %v", err)
		}

		config.AESKey = decryptedAESKey
		log.Println("Loaded AES key from database.")
	}

	log.Printf("Configuration loaded: LogLevel=%s, DBPath=%s, Port=%s", config.LogLevel, config.DBPath, config.Port)
}

func initDatabase() {
	var err error
	if _, err := os.Stat(config.DBPath); os.IsNotExist(err) {
		if err := os.MkdirAll(config.DBPath, os.ModePerm); err != nil {
			log.Fatalf("Failed to create data directory: %v", err)
		}
	}
	dbFilePath := fmt.Sprintf("%s/pasties.db", config.DBPath)
	db, err = gorm.Open(sqlite.Open(dbFilePath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	if err := db.AutoMigrate(&Pastie{}, &AppConfig{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func serveCreateForm(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/form.html")
	if err != nil {
		http.Error(w, "Error loading form template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func createPaste(w http.ResponseWriter, r *http.Request) {
	content := r.FormValue("content")
	if content == "" {
		http.Error(w, "Content cannot be empty", http.StatusBadRequest)
		return
	}

	sanitizedContent := html.EscapeString(content)
	encryptedContent, err := encrypt(sanitizedContent, config.AESKey)
	if err != nil {
		http.Error(w, "Failed to encrypt content", http.StatusInternalServerError)
		return
	}

	pastie := Pastie{
		ID:        generateID(),
		Content:   encryptedContent,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Default expiration
	}

	go func() {
		if err := db.Create(&pastie).Error; err != nil {
			log.Printf("Failed to save pastie: %v", err)
		}
	}()

	http.Redirect(w, r, fmt.Sprintf("/pastie/%s", pastie.ID), http.StatusSeeOther)
}

func getPaste(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var pastie Pastie
	if err := db.First(&pastie, "id = ?", id).Error; err != nil {
		http.Error(w, "Pastie not found", http.StatusNotFound)
		return
	}

	decryptedContent, err := decrypt(pastie.Content, config.AESKey)
	if err != nil {
		http.Error(w, "Failed to decrypt content", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/view_pastie.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, map[string]string{"Content": decryptedContent})
}

func adminPasties(w http.ResponseWriter, r *http.Request) {
	var pasties []Pastie
	if err := db.Find(&pasties).Error; err != nil {
		http.Error(w, "Failed to retrieve pasties", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/admin.html")
	if err != nil {
		http.Error(w, "Error loading admin template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, pasties)
}

func startExpiredPastiesCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			log.Println("Running cleanup for expired pasties...")
			db.Where("expires_at <= ?", time.Now()).Delete(&Pastie{})
		}
	}()
}

func encrypt(plainText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	_, err = rand.Read(iv)
	if err != nil {
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
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return string(data), nil
}

func generateID() string {
	b := make([]byte, 12)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Failed to generate ID: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// EncryptAES encrypts plaintext using a given master key
func EncryptAES(plaintext string, masterKey string) (string, error) {
	block, err := aes.NewCipher([]byte(masterKey))
	if err != nil {
		return "", err
	}

	plaintextBytes := []byte(plaintext)
	ciphertext := make([]byte, aes.BlockSize+len(plaintextBytes))
	iv := ciphertext[:aes.BlockSize]

	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintextBytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts ciphertext using a given master key
func DecryptAES(ciphertext string, masterKey string) (string, error) {
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

// GenerateRandomAESKey generates a random 32-byte AES key
func GenerateRandomAESKey() string {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate AES key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}
