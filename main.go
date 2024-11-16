// PastiePie 0.7
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
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var db *gorm.DB
var log = logrus.New()
var configLock sync.RWMutex
var config Config

// Config struct to store global settings
type Config struct {
	LogLevel    string `mapstructure:"log_level"`
	AESKey      string `mapstructure:"aes_key"`
	SSLCertPath string `mapstructure:"ssl_cert_path"`
	SSLKeyPath  string `mapstructure:"ssl_key_path"`
	DBPath      string `mapstructure:"db_path"`
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
	initLogging()
	initDatabase()
	defer func() {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}()

	// Start cleanup routine for expired pasties
	startExpiredPastiesCleanup(10 * time.Minute)

	// Start an HTTP server to redirect to HTTPS
	go func() {
		log.Info("HTTP server starting at :8080, redirecting to HTTPS")
		if err := http.ListenAndServe(":8080", http.HandlerFunc(redirectToHTTPS)); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	// Start the HTTPS server
	r := mux.NewRouter()
	r.HandleFunc("/", serveCreateForm).Methods("GET")
	r.HandleFunc("/pastie", createPaste).Methods("POST")
	r.HandleFunc("/pastie/{id}", getPaste).Methods("GET", "POST")
	r.HandleFunc("/admin/pasties", adminPasties).Methods("GET")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	log.Infof("PastiePie server starting at :8443 (HTTPS), cert: %s, key: %s", config.SSLCertPath, config.SSLKeyPath)
	if err := http.ListenAndServeTLS(":8443", config.SSLCertPath, config.SSLKeyPath, handlers.CORS(handlers.AllowedOrigins([]string{"*"}))(r)); err != nil {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}
}

func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Unable to decode config: %v", err)
	}

	if len(config.AESKey) != 32 {
		log.Fatalf("AES key must be 32 bytes for AES-256 encryption. Current length: %d", len(config.AESKey))
	}
}

func initLogging() {
	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		log.Warnf("Invalid log level in config, defaulting to 'info'")
		level = logrus.InfoLevel
	}
	log.SetLevel(level)
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
	if err := db.AutoMigrate(&Pastie{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
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
	password := r.FormValue("password")
	viewOnce := r.FormValue("view_once") == "true"
	expiration := r.FormValue("expiration")

	log.Infof("Creating new pastie with viewOnce: %v, expiration: %s", viewOnce, expiration) // Debug log

	if content == "" {
		http.Error(w, "Content cannot be empty", http.StatusBadRequest)
		return
	}

	// Set expiration time based on user input
	var expiresAt time.Time
	if expiration == "forever" {
		expiresAt = time.Time{} // Zero value of time.Time to represent "no expiration"
	} else {
		switch expiration {
		case "5min":
			expiresAt = time.Now().Add(5 * time.Minute)
		case "30min":
			expiresAt = time.Now().Add(30 * time.Minute)
		case "1hour":
			expiresAt = time.Now().Add(1 * time.Hour)
		case "1day":
			expiresAt = time.Now().Add(24 * time.Hour)
		case "7days":
			expiresAt = time.Now().Add(7 * 24 * time.Hour)
		default:
			expiresAt = time.Now().Add(24 * time.Hour) // Default to 1 day if not specified
		}
	}

	// Sanitize content
	sanitizedContent := html.EscapeString(content)

	// Encrypt content
	encryptedContent, err := encrypt(sanitizedContent, config.AESKey)
	if err != nil {
		http.Error(w, "Failed to encrypt content", http.StatusInternalServerError)
		return
	}

	// Create pastie object
	pastie := Pastie{
		ID:        generateID(),
		Content:   encryptedContent,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		ViewOnce:  viewOnce,
	}

	// If password is provided, hash it
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		pastie.PasswordHash = string(hash)
	}

	// Save pastie asynchronously
	go func() {
		if err := db.Create(&pastie).Error; err != nil {
			log.Errorf("Failed to save pastie: %v", err)
		} else {
			log.Infof("Successfully created pastie with ID: %s, viewOnce: %v", pastie.ID, pastie.ViewOnce)
		}
	}()

	// Generate the link to share
	link := fmt.Sprintf("https://%s/pastie/%s", r.Host, pastie.ID)

	tmpl, err := template.ParseFiles("templates/share_link.html")
	if err != nil {
		http.Error(w, "Error loading share link template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, map[string]string{"Link": link, "ViewOnce": fmt.Sprintf("%v", viewOnce)})
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

func getPaste(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var pastie Pastie
	if err := db.First(&pastie, "id = ?", id).Error; err != nil {
		http.Error(w, "Pastie not found", http.StatusNotFound)
		return
	}

	// Check if the pastie has expired
	if !pastie.ExpiresAt.IsZero() && time.Now().After(pastie.ExpiresAt) {
		log.Infof("Deleting expired pastie with ID: %s", pastie.ID) // Debug log for expired pastie
		db.Delete(&pastie)
		http.Error(w, "This pastie has expired.", http.StatusGone)
		return
	}

	// Check if the pastie is view-once and already viewed
	if pastie.ViewOnce && pastie.Viewed {
		http.Error(w, "Pastie not found", http.StatusNotFound)
		return
	}

	// Handle password-protected pastie
	if pastie.PasswordHash != "" {
		if r.Method == http.MethodGet {
			tmpl, err := template.ParseFiles("templates/password_prompt.html")
			if err != nil {
				http.Error(w, "Error loading password prompt template", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, map[string]string{"PastieID": id})
			return
		}

		if r.Method == http.MethodPost {
			password := r.FormValue("password")
			if password == "" {
				http.Error(w, "Password is required to view this pastie", http.StatusUnauthorized)
				return
			}
			if err := bcrypt.CompareHashAndPassword([]byte(pastie.PasswordHash), []byte(password)); err != nil {
				http.Error(w, "Invalid password", http.StatusUnauthorized)
				return
			}
		}
	}

	// Decrypt content
	decryptedContent, err := decrypt(pastie.Content, config.AESKey)
	if err != nil {
		http.Error(w, "Failed to decrypt content", http.StatusInternalServerError)
		return
	}

	// For view-once pasties, mark as viewed and delete immediately
	if pastie.ViewOnce {
		log.Infof("Viewing and deleting view-once pastie with ID: %s", pastie.ID) // Debug log for view-once
		pastie.Viewed = true
		if err := db.Delete(&pastie).Error; err != nil {
			log.Errorf("Failed to delete view-once pastie: %v", err)
			http.Error(w, "Failed to delete pastie after viewing", http.StatusInternalServerError)
			return
		}
	} else {
		pastie.Viewed = true
		if err := db.Save(&pastie).Error; err != nil {
			log.Errorf("Failed to update pastie as viewed: %v", err)
		}
	}

	tmpl, err := template.ParseFiles("templates/view_pastie.html")
	if err != nil {
		http.Error(w, "Error loading view pastie template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, map[string]string{"Content": decryptedContent})
}

func startExpiredPastiesCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			log.Info("Running expired pasties cleanup...")
			now := time.Now()
			if err := db.Where("expires_at <= ?", now).Delete(&Pastie{}).Error; err != nil {
				log.Errorf("Failed to clean up expired pasties: %v", err)
			} else {
				log.Info("Expired pasties cleanup completed.")
			}
		}
	}()
}

func generateID() string {
	b := make([]byte, 12) // 12 bytes = 96 bits, encoded as base64 becomes 16 characters
	_, err := rand.Read(b)
	if err != nil {
		log.Errorf("Failed to generate random ID: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func encrypt(plainText, key string) (string, error) {
	if len(key) != 32 {
		return "", errors.New("invalid key size; must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plainText))

	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func decrypt(cipherText, key string) (string, error) {
	if len(key) != 32 {
		return "", errors.New("invalid key size; must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	decodedCipherText, _ := base64.URLEncoding.DecodeString(cipherText)
	if len(decodedCipherText) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := decodedCipherText[:aes.BlockSize]
	decodedCipherText = decodedCipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decodedCipherText, decodedCipherText)

	return string(decodedCipherText), nil
}
