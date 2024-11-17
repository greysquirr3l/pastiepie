package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gtank/cryptopasta"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

var (
	db          *gorm.DB
	configLock  sync.RWMutex
	config      Config
	appLogger   = logrus.New()
	rateLimiter = rate.NewLimiter(1, 3) // Allow 1 request per second, burst of 3
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

	// Graceful Shutdown
	srv := &http.Server{
		Addr:    ":" + config.Port,
		Handler: handlers.CORS(handlers.AllowedOrigins([]string{"*"}))(r),
	}

	go func() {
		appLogger.Infof("Server starting on port %s", config.Port)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			appLogger.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	// Handle graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		appLogger.Fatalf("Server Shutdown Failed: %v", err)
	}
	appLogger.Info("Server exited properly")
}

// Secure ID Generation Function
func generateSecureID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Middleware: Recovery to Prevent Crashes
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				appLogger.WithField("error", rec).Error("Panic recovered")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Middleware: Rate Limiting
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rateLimiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware: Request Size Limit
func requestSizeLimitMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// Logger Initialization
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

// Generate AES Key
func generateAESKey() [32]byte {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		appLogger.Fatalf("Failed to generate AES key: %v", err)
	}
	return key
}

// Store AES Key in the Database
func storeAESKey(aesKey [32]byte, masterKey string) {
	encryptedAESKey, err := cryptopasta.Encrypt(aesKey[:], (*[32]byte)([]byte(masterKey)))
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

// Start Expired Pasties Cleanup
func startExpiredPastiesCleanup(interval time.Duration) {
	appLogger.Infof("Starting expired pasties cleanup routine. Interval: %s", interval)

	ticker := time.NewTicker(interval)

	go func() {
		for range ticker.C {
			appLogger.Info("Running cleanup for expired pasties...")
			err := db.Where("expires_at <= ? AND expires_at != ?", time.Now().UTC(), time.Time{}).Delete(&Pastie{}).Error
			if err != nil {
				appLogger.Errorf("Failed to clean up expired pasties: %v", err)
			} else {
				appLogger.Info("Expired pasties cleanup completed successfully.")
			}
		}
	}()
}

func setupRouter() *mux.Router {
	r := mux.NewRouter()
	r.Use(recoveryMiddleware)                      // Recovery middleware to prevent crashes
	r.Use(rateLimitMiddleware)                     // Rate limiting middleware
	r.Use(requestSizeLimitMiddleware(1024 * 1024)) // Limit request size to 1MB

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

// Serve Create Form Handler
func serveCreateForm(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/form.html")
	if err != nil {
		renderErrorPage(w, "Error loading form template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// Create Paste Handler
func createPaste(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	content := r.FormValue("content")
	if content == "" {
		renderErrorPage(w, "Content cannot be empty", http.StatusBadRequest)
		return
	}

	viewOnce := r.FormValue("view_once") == "true"
	expirationString := r.FormValue("expiration")

	// Set expiration time based on user selection
	var expiration time.Time
	switch expirationString {
	case "5min":
		expiration = time.Now().UTC().Add(5 * time.Minute)
	case "30min":
		expiration = time.Now().UTC().Add(30 * time.Minute)
	case "1hour":
		expiration = time.Now().UTC().Add(1 * time.Hour)
	case "1day":
		expiration = time.Now().UTC().Add(24 * time.Hour)
	case "7days":
		expiration = time.Now().UTC().Add(7 * 24 * time.Hour)
	case "forever":
		expiration = time.Time{}
	default:
		renderErrorPage(w, fmt.Sprintf("Invalid expiration duration: %s", expirationString), http.StatusBadRequest)
		return
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

	// Sanitize and Encrypt Content
	sanitizedContent := html.EscapeString(content)
	var aesKey [32]byte
	copy(aesKey[:], config.AESKey[:])
	encryptedContent, err := cryptopasta.Encrypt([]byte(sanitizedContent), &aesKey)
	if err != nil {
		appLogger.Errorf("Encryption failed: %v", err)
		renderErrorPage(w, "Failed to encrypt content", http.StatusInternalServerError)
		return
	}

	// Generate Secure ID
	id, err := generateSecureID()
	if err != nil {
		renderErrorPage(w, "Failed to generate secure ID", http.StatusInternalServerError)
		return
	}

	pastie := Pastie{
		ID:           id,
		Content:      base64.StdEncoding.EncodeToString(encryptedContent),
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    expiration,
		ViewOnce:     viewOnce,
		Viewed:       false,
	}

	// Save the pastie in the background
	go func() {
		if err := db.WithContext(ctx).Create(&pastie).Error; err != nil {
			appLogger.Errorf("Failed to save pastie: %v", err)
		}
	}()

	shareLink := fmt.Sprintf("http://%s/pastie/%s", r.Host, pastie.ID)
	timeoutRemaining := formatDuration(expiration.Sub(time.Now().UTC()))

	data := map[string]interface{}{
		"Link":              shareLink,
		"PasswordProtected": password != "",
		"TimeoutRemaining":  timeoutRemaining,
		"ViewOnce":          viewOnce,
	}

	tmpl, err := template.ParseFiles("templates/share_link.html")
	if err != nil {
		appLogger.Errorf("Error loading share_link.html template: %v", err)
		renderErrorPage(w, "Error loading share link page", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		appLogger.Errorf("Error rendering share_link.html template: %v", err)
		renderErrorPage(w, "Error rendering share link page", http.StatusInternalServerError)
		return
	}
}

// Get Paste Handler
func getPaste(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	id := mux.Vars(r)["id"]

	var pastie Pastie
	if err := db.WithContext(ctx).First(&pastie, "id = ?", id).Error; err != nil {
		appLogger.Errorf("Failed to find pastie: %v", err)
		renderErrorPage(w, "Pastie not found", http.StatusNotFound)
		return
	}

	// Handle password-protected pastie
	if pastie.PasswordHash != "" && r.Method != http.MethodPost {
		tmpl, err := template.ParseFiles("templates/password_prompt.html")
		if err != nil {
			appLogger.Errorf("Failed to load password prompt template: %v", err)
			renderErrorPage(w, "Failed to load password prompt page", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, map[string]string{"PastieID": id})
		return
	}

	// Validate the password if the pastie is password-protected
	if pastie.PasswordHash != "" {
		password := r.FormValue("password")
		if err := bcrypt.CompareHashAndPassword([]byte(pastie.PasswordHash), []byte(password)); err != nil {
			appLogger.Warnf("Password validation failed for pastie %s: %v", id, err)
			renderErrorPage(w, "Incorrect password", http.StatusUnauthorized)
			return
		}
	}

	// Decrypt content
	cipherBytes, err := base64.StdEncoding.DecodeString(pastie.Content)
	if err != nil {
		appLogger.Errorf("Failed to decode content for pastie %s: %v", id, err)
		renderErrorPage(w, "Failed to decode content", http.StatusInternalServerError)
		return
	}

	var aesKey [32]byte
	copy(aesKey[:], config.AESKey[:])

	decryptedContent, err := cryptopasta.Decrypt(cipherBytes, &aesKey)
	if err != nil {
		appLogger.Errorf("Failed to decrypt content for pastie %s: %v", id, err)
		renderErrorPage(w, "Failed to decrypt content", http.StatusInternalServerError)
		return
	}

	// Update the viewed status for pasties
	if !pastie.Viewed || pastie.ViewOnce {
		pastie.Viewed = true
		if pastie.ViewOnce {
			if err := db.WithContext(ctx).Delete(&pastie).Error; err != nil {
				appLogger.Errorf("Failed to delete one-time pastie %s: %v", id, err)
			}
		} else {
			if err := db.WithContext(ctx).Save(&pastie).Error; err != nil {
				appLogger.Errorf("Failed to update pastie %s as viewed: %v", id, err)
			}
		}
	}

	tmpl, err := template.ParseFiles("templates/view_pastie.html")
	if err != nil {
		renderErrorPage(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, map[string]string{"Content": string(decryptedContent)})
}

// Admin Handler to View All Pasties
func adminPasties(w http.ResponseWriter, r *http.Request) {
	var pasties []Pastie
	if err := db.Find(&pasties).Error; err != nil {
		renderErrorPage(w, "Failed to load pasties", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/admin.html")
	if err != nil {
		renderErrorPage(w, "Failed to load admin page", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, pasties)
	if err != nil {
		appLogger.Errorf("Failed to execute admin template: %v", err)
		renderErrorPage(w, "Failed to render admin page", http.StatusInternalServerError)
		return
	}
}

// Delete Specific Pastie Handler
func deletePastieHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := db.Delete(&Pastie{}, "id = ?", id).Error; err != nil {
		appLogger.Errorf("Failed to delete pastie: %s, %v", id, err)
		renderErrorPage(w, "Failed to delete pastie", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/pasties", http.StatusSeeOther)
}

// Delete All Pasties Handler
func deleteAllPastiesHandler(w http.ResponseWriter, r *http.Request) {
	if err := db.Where("expires_at <= ? AND expires_at != ?", time.Now().UTC(), time.Time{}).Delete(&Pastie{}).Error; err != nil {
		appLogger.Errorf("Failed to delete all pasties: %v", err)
		renderErrorPage(w, "Failed to delete all pasties", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/pasties", http.StatusSeeOther)
}

// Health Check Handler
func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Regenerate AES Key Handler
func regenerateAESKeyHandler(w http.ResponseWriter, r *http.Request) {
	newAESKey := generateAESKey()
	masterKey := os.Getenv("MASTER_KEY")
	storeAESKey(newAESKey, masterKey)
	copy(config.AESKey[:], newAESKey[:])
	appLogger.Info("Successfully regenerated and updated the AES key.")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("AES key successfully regenerated."))
}

// Render Error Page
func renderErrorPage(w http.ResponseWriter, message string, statusCode int) {
	tmpl, err := template.ParseFiles("templates/error.html")
	if err != nil {
		appLogger.Errorf("Error loading error.html template: %v", err)
		http.Error(w, "An unexpected error occurred", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(statusCode)
	err = tmpl.Execute(w, map[string]string{"ErrorMessage": message})
	if err != nil {
		appLogger.Errorf("Failed to execute error template: %v", err)
		http.Error(w, "An unexpected error occurred", http.StatusInternalServerError)
	}
}

// Database Initialization
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

// Configuration Initialization
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
		aesKey := generateAESKey()
		copy(config.AESKey[:], aesKey[:])
		storeAESKey(config.AESKey, masterKey)
	} else if result.Error != nil {
		appLogger.Fatalf("Failed to query database for AES key: %v", result.Error)
	} else {
		appLogger.Info("AES key found in database. Decrypting...")
		encryptedAESKeyBytes, err := base64.StdEncoding.DecodeString(storedKey.EncryptedAESKey)
		if err != nil {
			appLogger.Fatalf("Failed to decode stored AES key: %v", err)
		}
		decryptedAESKeyBytes, err := cryptopasta.Decrypt(encryptedAESKeyBytes, (*[32]byte)([]byte(masterKey)))
		if err != nil {
			appLogger.Fatalf("Failed to decrypt stored AES key: %v", err)
		}
		copy(config.AESKey[:], decryptedAESKeyBytes[:])
		appLogger.Info("Loaded AES key from database.")
	}
}

// Format Duration to Human-Readable String
func formatDuration(d time.Duration) string {
	h := int64(d.Hours())
	m := int64(d.Minutes()) % 60
	s := int64(d.Seconds()) % 60
	return fmt.Sprintf("%dh%dm%ds", h, m, s)
}
