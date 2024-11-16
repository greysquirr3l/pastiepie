package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var db *gorm.DB
var log = logrus.New()
var configLock sync.RWMutex

type Config struct {
	LogLevel string
	DBPath   string
	AESKey   string
}

var config Config

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

	// Set up routes
	r := mux.NewRouter()
	r.HandleFunc("/", serveCreateForm).Methods("GET")
	r.HandleFunc("/pastie", createPaste).Methods("POST")
	r.HandleFunc("/pastie/{id}", getPaste).Methods("GET", "POST")
	r.HandleFunc("/admin/pasties", adminPasties).Methods("GET")
	r.HandleFunc("/healthz", healthCheckHandler).Methods("GET")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// Start the HTTP server on port 8081
	log.Info("PastiePie server starting at :8081")
	if err := http.ListenAndServe(":8081", handlers.ProxyHeaders(r)); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func initConfig() {
	config.LogLevel = os.Getenv("LOG_LEVEL")
	config.DBPath = os.Getenv("DB_PATH")
	config.AESKey = os.Getenv("AES_KEY")

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

func adminPasties(w http.ResponseWriter, r *http.Request) {
	logRequestDetails(r)

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

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	logRequestDetails(r)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}

func logRequestDetails(r *http.Request) {
	log.Infof("Request Method: %s, Request URL: %s, Request Headers: %v", r.Method, r.URL, r.Header)
}
