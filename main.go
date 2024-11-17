package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gtank/cryptopasta"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	db         *gorm.DB
	configLock sync.RWMutex
	config     Config
	appLogger  = logrus.New()
)

// Config struct to store global settings
type Config struct {
	LogLevel string
	AESKey   [32]byte
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
			appLogger.Fatalf("Application panicked: %v", r)
		}
	}()

	appLogger.Info("Starting application...")

	initLogger()
	initConfig(true)
	initDatabase()
	initConfig(false)

	defer func() {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}()

	startExpiredPastiesCleanup(10 * time.Minute)
	r := setupRouter()

	appLogger.Infof("Server starting on port %s", config.Port)
	if err := http.ListenAndServe(":"+config.Port, handlers.CORS(handlers.AllowedOrigins([]string{"*"}))(r)); err != nil {
		appLogger.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func initLogger() {
	appLogger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logLevel, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	appLogger.SetLevel(logLevel)
	appLogger.Info("Logger initialized.")
}

func initConfig(loadOnly bool) {
	appLogger.Info("Initializing configuration...")

	viper.SetConfigFile("/root/config.yml")
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		appLogger.Fatalf("Error reading config file: %v", err)
	}

	config.LogLevel = viper.GetString("log_level")
	config.DBPath = viper.GetString("db_path")
	config.Port = viper.GetString("port")

	appLogger.Infof("Loaded configuration: LogLevel=%s, DBPath=%s, Port=%s", config.LogLevel, config.DBPath, config.Port)

	if loadOnly {
		return
	}

	masterKey := os.Getenv("MASTER_KEY")
	if len(masterKey) != 32 {
		appLogger.Fatalf("MASTER_KEY must be 32 bytes for AES-256 encryption.")
	}

	// Convert masterKey to [32]byte
	aesKey := convertKey(masterKey)

	var storedKey AppConfig
	result := db.First(&storedKey, "key_id = ?", "aes_key")
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		appLogger.Info("No AES key found, generating a new one...")
		config.AESKey = aesKey
		storeAESKey(config.AESKey)
	} else if result.Error != nil {
		appLogger.Fatalf("Failed to query database for AES key: %v", result.Error)
	} else {
		appLogger.Info("AES key found in database. Decrypting...")
		encryptedAESKeyBytes, err := base64.StdEncoding.DecodeString(storedKey.EncryptedAESKey)
		if err != nil {
			appLogger.Fatalf("Failed to decode stored AES key: %v", err)
		}
		decryptedAESKeyBytes, err := cryptopasta.Decrypt(encryptedAESKeyBytes, &aesKey)
		if err != nil {
			appLogger.Fatalf("Failed to decrypt stored AES key: %v", err)
		}
		if len(decryptedAESKeyBytes) != 32 {
			appLogger.Fatalf("Decrypted AES key is not 32 bytes. Found length: %d", len(decryptedAESKeyBytes))
		}
		copy(config.AESKey[:], decryptedAESKeyBytes[:32])
		appLogger.Info("Loaded AES key from database.")
	}
}

func storeAESKey(aesKey [32]byte) {
	masterKey := os.Getenv("MASTER_KEY")
	convertedKey := convertKey(masterKey)

	encryptedAESKey, err := cryptopasta.Encrypt(aesKey[:], &convertedKey)
	if err != nil {
		appLogger.Fatalf("Failed to encrypt the AES key: %v", err)
	}
	encryptedAESKeyString := base64.StdEncoding.EncodeToString(encryptedAESKey)

	var storedKey AppConfig
	result := db.First(&storedKey, "key_id = ?", "aes_key")
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		storedKey = AppConfig{
			KeyID:           "aes_key",
			EncryptedAESKey: encryptedAESKeyString,
		}
		if err := db.Create(&storedKey).Error; err != nil {
			appLogger.Fatalf("Failed to store AES key in database: %v", err)
		}
	} else {
		storedKey.EncryptedAESKey = encryptedAESKeyString
		if err := db.Save(&storedKey).Error; err != nil {
			appLogger.Fatalf("Failed to update AES key in database: %v", err)
		}
	}
	appLogger.Info("AES key successfully stored in the database.")
}

func convertKey(keyString string) [32]byte {
	var key [32]byte
	copy(key[:], keyString)
	return key
}

func initDatabase() {
	appLogger.Info("Initializing database...")

	if config.DBPath == "" {
		appLogger.Fatalf("Database path is empty. Check your config file or environment variables.")
	}

	if _, err := os.Stat(config.DBPath); os.IsNotExist(err) {
		appLogger.Infof("Data directory does not exist at %s. Creating it...", config.DBPath)
		if err := os.MkdirAll(config.DBPath, os.ModePerm); err != nil {
			appLogger.Fatalf("Failed to create data directory: %v", err)
		}
	}

	dbFilePath := fmt.Sprintf("%s/pasties.db", config.DBPath)
	appLogger.Infof("Using database file: %s", dbFilePath)

	var err error
	db, err = gorm.Open(sqlite.Open(dbFilePath), &gorm.Config{})
	if err != nil {
		appLogger.Fatalf("Failed to connect to database: %v", err)
	}

	appLogger.Info("Applying database migrations...")
	if err := db.AutoMigrate(&Pastie{}, &AppConfig{}); err != nil {
		appLogger.Fatalf("Failed to migrate database: %v", err)
	}
	appLogger.Info("Database initialized successfully.")
}

func setupRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/", serveCreateForm).Methods("GET")
	r.HandleFunc("/pastie", createPaste).Methods("POST")
	r.HandleFunc("/pastie/{id}", getPaste).Methods("GET", "POST")
	r.HandleFunc("/admin/pasties", adminPasties).Methods("GET")
	r.HandleFunc("/admin/pasties/delete/{id}", deletePastieHandler).Methods("POST")
	r.HandleFunc("/admin/pasties/delete-all", deleteAllPastiesHandler).Methods("POST")
	r.HandleFunc("/healthz", healthCheck).Methods("GET")
	r.HandleFunc("/admin/regenerate-aes-key", regenerateAESKeyHandler).Methods("POST")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	return r
}

func adminPasties(w http.ResponseWriter, r *http.Request) {
	var pasties []Pastie
	if err := db.Find(&pasties).Error; err != nil {
		renderErrorPage(w, "Failed to retrieve pasties", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/admin.html")
	if err != nil {
		renderErrorPage(w, "Error loading admin template", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, pasties)
}

func getPaste(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var pastie Pastie
	if err := db.First(&pastie, "id = ?", id).Error; err != nil {
		renderErrorPage(w, "Pastie not found", http.StatusNotFound)
		return
	}

	if pastie.ViewOnce && pastie.Viewed {
		renderErrorPage(w, "This pastie has already been viewed", http.StatusGone)
		return
	}

	if !pastie.ExpiresAt.IsZero() && time.Now().After(pastie.ExpiresAt) {
		db.Delete(&pastie)
		renderErrorPage(w, "This pastie has expired", http.StatusGone)
		return
	}

	if pastie.PasswordHash != "" {
		if r.Method == http.MethodGet {
			tmpl, err := template.ParseFiles("templates/password_prompt.html")
			if err != nil {
				appLogger.Errorf("Error loading password_prompt.html template: %v", err)
				renderErrorPage(w, "An error occurred", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, map[string]string{"PastieID": pastie.ID})
			return
		}

		password := r.FormValue("password")
		if err := bcrypt.CompareHashAndPassword([]byte(pastie.PasswordHash), []byte(password)); err != nil {
			renderErrorPage(w, "Incorrect password", http.StatusUnauthorized)
			return
		}
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(pastie.Content)
	if err != nil {
		appLogger.Errorf("Failed to decode content: %v", err)
		renderErrorPage(w, "Failed to decode content", http.StatusInternalServerError)
		return
	}

	decryptedContent, err := cryptopasta.Decrypt(cipherBytes, &config.AESKey)
	if err != nil {
		renderErrorPage(w, "Failed to decrypt content", http.StatusInternalServerError)
		return
	}

	if pastie.ViewOnce {
		pastie.Viewed = true
		if err := db.Save(&pastie).Error; err != nil {
			appLogger.Errorf("Failed to update pastie as viewed: %v", err)
		}
	}

	tmpl, err := template.ParseFiles("templates/view_pastie.html")
	if err != nil {
		renderErrorPage(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, map[string]string{"Content": string(decryptedContent)})
}

func deletePastieHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := db.Delete(&Pastie{}, "id = ?", id).Error; err != nil {
		appLogger.Errorf("Failed to delete pastie: %s, %v", id, err)
		renderErrorPage(w, "Failed to delete pastie", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/pasties", http.StatusSeeOther)
}

func deleteAllPastiesHandler(w http.ResponseWriter, r *http.Request) {
	if err := db.Where("expires_at != ?", time.Time{}).Delete(&Pastie{}).Error; err != nil {
		appLogger.Errorf("Failed to delete all pasties: %v", err)
		renderErrorPage(w, "Failed to delete all pasties", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/pasties", http.StatusSeeOther)
}

func startExpiredPastiesCleanup(interval time.Duration) {
	appLogger.Infof("Starting expired pasties cleanup routine. Interval: %s", interval)

	ticker := time.NewTicker(interval)

	go func() {
		for range ticker.C {
			appLogger.Info("Running cleanup for expired pasties...")
			err := db.Where("expires_at <= ? AND expires_at != ?", time.Now(), time.Time{}).Delete(&Pastie{}).Error
			if err != nil {
				appLogger.Errorf("Failed to clean up expired pasties: %v", err)
			} else {
				appLogger.Info("Expired pasties cleanup completed successfully.")
			}
		}
	}()
}

func renderErrorPage(w http.ResponseWriter, message string, statusCode int) {
	tmpl, err := template.ParseFiles("templates/error.html")
	if err != nil {
		appLogger.Errorf("Error loading error.html template: %v", err)
		http.Error(w, "An unexpected error occurred", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(statusCode)
	tmpl.Execute(w, map[string]string{"ErrorMessage": message})
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func regenerateAESKeyHandler(w http.ResponseWriter, r *http.Request) {
	newAESKey := cryptopasta.NewEncryptionKey()
	storeAESKey(*newAESKey)
	config.AESKey = *newAESKey
	appLogger.Info("Successfully regenerated and updated the AES key.")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("AES key successfully regenerated."))
}

func generateID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		appLogger.Errorf("Failed to generate random ID: %v", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func encrypt(plainText []byte, key *[32]byte) ([]byte, error) {
	encryptedContent, err := cryptopasta.Encrypt(plainText, key)
	if err != nil {
		appLogger.Errorf("Encryption failed: %v", err)
		return nil, err
	}
	return encryptedContent, nil
}

func decrypt(cipherText []byte, key *[32]byte) ([]byte, error) {
	decryptedContent, err := cryptopasta.Decrypt(cipherText, key)
	if err != nil {
		appLogger.Errorf("Decryption failed: %v", err)
		return nil, err
	}
	return decryptedContent, nil
}

func serveCreateForm(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/form.html")
	if err != nil {
		renderErrorPage(w, "Error loading form template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func createPaste(w http.ResponseWriter, r *http.Request) {
	content := r.FormValue("content")
	if content == "" {
		renderErrorPage(w, "Content cannot be empty", http.StatusBadRequest)
		return
	}

	viewOnce := r.FormValue("view_once") == "true"
	expirationString := r.FormValue("expiration")
	var expiration time.Time
	if expirationString == "forever" {
		expiration = time.Time{}
	} else {
		expiration = time.Now().Add(7 * 24 * time.Hour) // Default to 7 days if not "forever"
	}

	password := r.FormValue("password")
	var passwordHash string
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			renderErrorPage(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		passwordHash = string(hash)
	}

	sanitizedContent := html.EscapeString(content)
	encryptedContent, err := encrypt([]byte(sanitizedContent), &config.AESKey)
	if err != nil {
		renderErrorPage(w, "Failed to encrypt content", http.StatusInternalServerError)
		return
	}

	pastie := Pastie{
		ID:           generateID(),
		Content:      base64.StdEncoding.EncodeToString(encryptedContent),
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		ExpiresAt:    expiration,
		ViewOnce:     viewOnce,
		Viewed:       false,
	}

	// Save the pastie in the background
	go func() {
		if err := db.Create(&pastie).Error; err != nil {
			appLogger.Errorf("Failed to save pastie: %v", err)
		}
	}()

	// Prepare data for the share_link template
	shareLink := fmt.Sprintf("http://%s/pastie/%s", r.Host, pastie.ID)
	timeoutRemaining := "Never"
	if !expiration.IsZero() {
		timeoutRemaining = expiration.Sub(time.Now()).String()
	}

	data := map[string]interface{}{
		"Link":              shareLink,
		"PasswordProtected": password != "",
		"TimeoutRemaining":  timeoutRemaining,
		"ViewOnce":          viewOnce,
	}

	// Load and execute share_link.html with the generated link
	tmpl, err := template.ParseFiles("templates/share_link.html")
	if err != nil {
		renderErrorPage(w, "Error loading share link page", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		renderErrorPage(w, "Error rendering share link page", http.StatusInternalServerError)
		return
	}
}
