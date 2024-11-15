//pastiepie 0.1

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB
var log = logrus.New()
var configLock sync.RWMutex
var config Config

// Config struct to store global settings
type Config struct {
	LogLevel string `mapstructure:"log_level"`
	AESKey   string `mapstructure:"aes_key"`
}

// Pastie struct to store each pastie
type Pastie struct {
	ID           string `gorm:"primary_key"`
	Content      string
	PasswordHash string
	CreatedAt    time.Time
	ViewOnce     bool
	Viewed       bool
}

func main() {
	initConfig()
	initLogging()
	initDatabase()
	defer db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/", serveCreateForm).Methods("GET")
	r.HandleFunc("/pastie", createPaste).Methods("POST")
	r.HandleFunc("/pastie/{id}", getPaste).Methods("GET")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	log.Info("PastiePie server starting at :8080")
	http.ListenAndServeTLS(":8080", "server.crt", "server.key", handlers.CORS(handlers.AllowedOrigins([]string{"*"}))(r))
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
	dbPath := "/data/pasties.db"
	if _, err := os.Stat("/data"); os.IsNotExist(err) {
		if err := os.Mkdir("/data", os.ModePerm); err != nil {
			log.Fatalf("Failed to create data directory: %v", err)
		}
	}
	db, err = gorm.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	db.AutoMigrate(&Pastie{})
}

func serveCreateForm(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/form.html")
}

func createPaste(w http.ResponseWriter, r *http.Request) {
	content := r.FormValue("content")
	password := r.FormValue("password")
	viewOnce := r.FormValue("view_once") == "true"

	if content == "" {
		http.Error(w, "Content cannot be empty", http.StatusBadRequest)
		return
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
		}
	}()

	http.Redirect(w, r, fmt.Sprintf("/pastie/%s", pastie.ID), http.StatusSeeOther)
}

func getPaste(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var pastie Pastie
	if err := db.First(&pastie, "id = ?", id).Error; err != nil {
		http.Error(w, "Pastie not found", http.StatusNotFound)
		return
	}

	if pastie.ViewOnce && pastie.Viewed {
		http.Error(w, "Pastie not found", http.StatusNotFound)
		return
	}

	if pastie.PasswordHash != "" {
		password := r.FormValue("password")
		if password == "" {
			http.Error(w, "Password required to view this pastie", http.StatusUnauthorized)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(pastie.PasswordHash), []byte(password)); err != nil {
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}
	}

	decryptedContent, err := decrypt(pastie.Content, config.AESKey)
	if err != nil {
		http.Error(w, "Failed to decrypt content", http.StatusInternalServerError)
		return
	}

	// Mark pastie as viewed if it is a view-once pastie
	if pastie.ViewOnce {
		pastie.Viewed = true
		db.Save(&pastie)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Pastie content: %s\n", decryptedContent)
	if pastie.ViewOnce {
		fmt.Fprintf(w, "Note: This pastie was set to be viewable only once and is now deleted.")
	}
}

func generateID() string {
	b := make([]byte, 12) // Increase length for better security
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

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plainText))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(cipherText, key string) (string, error) {
	if len(key) != 32 {
		return "", errors.New("invalid key size; must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	ciphertext, _ := base64.URLEncoding.DecodeString(cipherText)
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
