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
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
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

	var storedKey AppConfig
	result := db.First(&storedKey, "key_id = ?", "aes_key")
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		appLogger.Info("No AES key found, generating a new one...")
		config.AESKey = GenerateRandomAESKey()
		storeAESKey(config.AESKey)
	} else if result.Error != nil {
		appLogger.Fatalf("Failed to query database for AES key: %v", result.Error)
	} else {
		appLogger.Info("AES key found in database. Decrypting...")
		decryptedAESKey, err := DecryptAES(storedKey.EncryptedAESKey, masterKey)
		if err != nil {
			appLogger.Fatalf("Failed to decrypt stored AES key: %v", err)
		}
		config.AESKey = decryptedAESKey
		appLogger.Info("Loaded AES key from database.")
	}

	if !validateAESKey(config.AESKey) {
		appLogger.Warn("Invalid AES key detected. Regenerating...")
		config.AESKey = GenerateRandomAESKey()
		storeAESKey(config.AESKey)
	}
}

func storeAESKey(aesKey string) {
	masterKey := os.Getenv("MASTER_KEY")
	encryptedAESKey, err := EncryptAES(aesKey, masterKey)
	if err != nil {
		appLogger.Fatalf("Failed to encrypt the AES key: %v", err)
	}
	var storedKey AppConfig
	result := db.First(&storedKey, "key_id = ?", "aes_key")
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		storedKey = AppConfig{
			KeyID:           "aes_key",
			EncryptedAESKey: encryptedAESKey,
		}
		if err := db.Create(&storedKey).Error; err != nil {
			appLogger.Fatalf("Failed to store AES key in database: %v", err)
		}
	} else {
		storedKey.EncryptedAESKey = encryptedAESKey
		if err := db.Save(&storedKey).Error; err != nil {
			appLogger.Fatalf("Failed to update AES key in database: %v", err)
		}
	}
	appLogger.Info("AES key successfully stored in the database.")
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

	db, err := gorm.Open(sqlite.Open(dbFilePath), &gorm.Config{})
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
	r.HandleFunc("/healthz", healthCheck).Methods("GET")
	r.HandleFunc("/admin/regenerate-aes-key", regenerateAESKeyHandler).Methods("POST")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	return r
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
		appLogger.Errorf("Encryption failed: %v", err)
		http.Error(w, "Failed to encrypt content", http.StatusInternalServerError)
		return
	}

	pastie := Pastie{
		ID:        generateID(),
		Content:   encryptedContent,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	go func() {
		if err := db.Create(&pastie).Error; err != nil {
			appLogger.Errorf("Failed to save pastie: %v", err)
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
	// Define a struct to include the AESKey along with Pastie details
	type PastieWithKey struct {
		ID        string
		CreatedAt time.Time
		ExpiresAt time.Time
		ViewOnce  bool
		Viewed    bool
		AESKey    string
	}

	var pasties []Pastie
	// Query all pasties from the database
	if err := db.Find(&pasties).Error; err != nil {
		http.Error(w, "Failed to retrieve pasties", http.StatusInternalServerError)
		return
	}

	// Fetch MASTER_KEY for AES decryption
	masterKey := os.Getenv("MASTER_KEY")
	if len(masterKey) != 32 {
		http.Error(w, "Invalid MASTER_KEY length; must be 32 bytes.", http.StatusInternalServerError)
		return
	}

	// Create a slice to hold pasties with decrypted AES keys
	var pastiesWithKeys []PastieWithKey

	// Loop through each pastie and add the decrypted AES key
	for _, pastie := range pasties {
		var storedKey AppConfig
		if err := db.First(&storedKey, "key_id = ?", "aes_key").Error; err != nil {
			// Log the error and skip the pastie if AES key retrieval fails
			appLogger.Errorf("Failed to retrieve AES key for pastie ID %s: %v", pastie.ID, err)
			continue
		}

		// Decrypt the AES key
		decryptedKey, err := DecryptAES(storedKey.EncryptedAESKey, masterKey)
		if err != nil {
			appLogger.Errorf("Failed to decrypt AES key for pastie ID %s: %v", pastie.ID, err)
			continue
		}

		// Add the pastie with its decrypted AES key to the slice
		pastiesWithKeys = append(pastiesWithKeys, PastieWithKey{
			ID:        pastie.ID,
			CreatedAt: pastie.CreatedAt,
			ExpiresAt: pastie.ExpiresAt,
			ViewOnce:  pastie.ViewOnce,
			Viewed:    pastie.Viewed,
			AESKey:    decryptedKey,
		})
	}

	// Parse the admin.html template
	tmpl, err := template.ParseFiles("templates/admin.html")
	if err != nil {
		http.Error(w, "Error loading admin template", http.StatusInternalServerError)
		return
	}

	// Execute the template with the pastiesWithKeys data
	if err := tmpl.Execute(w, pastiesWithKeys); err != nil {
		http.Error(w, "Error rendering admin page", http.StatusInternalServerError)
	}
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func regenerateAESKeyHandler(w http.ResponseWriter, r *http.Request) {
	masterKey := os.Getenv("MASTER_KEY")
	if len(masterKey) != 32 {
		http.Error(w, "MASTER_KEY must be 32 bytes for AES-256 encryption.", http.StatusInternalServerError)
		return
	}

	newAESKey := GenerateRandomAESKey()
	storeAESKey(newAESKey)
	config.AESKey = newAESKey
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
	if len(key) != 32 {
		return "", errors.New("invalid key size; must be 32 bytes for AES-256 decryption")
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("failed to decode cipherText: %w", err)
	}

	if len(cipherBytes) < aes.BlockSize {
		return "", errors.New("ciphertext too short; missing initialization vector (IV)")
	}

	iv := cipherBytes[:aes.BlockSize]
	cipherBytes = cipherBytes[aes.BlockSize:]

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherBytes, cipherBytes)

	return string(cipherBytes), nil
}

func GenerateRandomAESKey() string {
	for {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			appLogger.Warnf("Failed to generate AES key: %v. Retrying...", err)
			continue
		}
		appLogger.Info("Successfully generated a 32-byte AES key.")
		return base64.StdEncoding.EncodeToString(key)
	}
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

func startExpiredPastiesCleanup(interval time.Duration) {
	appLogger.Infof("Starting expired pasties cleanup routine. Interval: %s", interval)

	ticker := time.NewTicker(interval)

	go func() {
		for range ticker.C {
			appLogger.Info("Running cleanup for expired pasties...")
			err := db.Where("expires_at <= ?", time.Now()).Delete(&Pastie{}).Error
			if err != nil {
				appLogger.Errorf("Failed to clean up expired pasties: %v", err)
			} else {
				appLogger.Info("Expired pasties cleanup completed successfully.")
			}
		}
	}()
}

func validateAESKey(key string) bool {
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(decodedKey) == 32
}
