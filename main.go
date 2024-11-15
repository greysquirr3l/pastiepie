// PastiePie 0.5
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "encoding/pem"
    "errors"
    "fmt"
		"html"
    "html/template"
    "io"
    "math/big"
    "net/http"
    "os"
    "sync"
    "time"

    "github.com/gorilla/handlers"
    "github.com/gorilla/mux"
    "github.com/glebarez/sqlite"
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
    LogLevel string `mapstructure:"log_level"`
    AESKey   string `mapstructure:"aes_key"`
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

    certPath := "server.crt"
    keyPath := "server.key"

    // Generate self-signed certificates if they don't exist
    if _, err := os.Stat(certPath); os.IsNotExist(err) || os.IsNotExist(err) {
        log.Info("SSL certificates not found, generating self-signed certificate...")
        if err := generateSelfSignedCertificate(certPath, keyPath); err != nil {
            log.Fatalf("Failed to generate self-signed certificate: %v", err)
        }
    }

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
    r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
		r.HandleFunc("/admin/pasties", adminPasties).Methods("GET")


    log.Info("PastiePie server starting at :8443 (HTTPS)")
    if err := http.ListenAndServeTLS(":8443", certPath, keyPath, handlers.CORS(handlers.AllowedOrigins([]string{"*"}))(r)); err != nil {
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
    dbPath := "/data/pasties.db"
    if _, err := os.Stat("/data"); os.IsNotExist(err) {
        if err := os.Mkdir("/data", os.ModePerm); err != nil {
            log.Fatalf("Failed to create data directory: %v", err)
        }
    }
    db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }
    if err := db.AutoMigrate(&Pastie{}); err != nil {
        log.Fatalf("Failed to migrate database: %v", err)
    }
}

func serveCreateForm(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFiles("templates/form.html")
    if err != nil {
        http.Error(w, "Error loading form template", http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

// Admin page handler to display all pasties
func adminPasties(w http.ResponseWriter, r *http.Request) {
    var pasties []Pastie
    if err := db.Find(&pasties).Error; err != nil {
        http.Error(w, "Failed to retrieve pasties", http.StatusInternalServerError)
        return
    }

    // Define a FuncMap to supply functions to the template
    funcMap := template.FuncMap{
        "now": time.Now,
        "sub": func(a, b int64) int64 { return a - b },
        "div": func(a, b int64) int64 { return a / b },
        "mod": func(a, b int64) int64 { return a % b },
    }

    tmpl, err := template.New("admin.html").Funcs(funcMap).ParseFiles("templates/admin.html")
    if err != nil {
        http.Error(w, "Error loading admin template", http.StatusInternalServerError)
        return
    }

    tmpl.Execute(w, pasties)
}

func createPaste(w http.ResponseWriter, r *http.Request) {
    content := r.FormValue("content")
    password := r.FormValue("password")
    viewOnce := r.FormValue("view_once") == "true"
    expiration := r.FormValue("expiration")

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
        // Remove expired pastie
        db.Delete(&pastie)
        http.Error(w, "This pastie has expired.", http.StatusGone)
        return
    }

    // Check if the pastie has been viewed already if it is a "view-once" pastie
    if pastie.ViewOnce && pastie.Viewed {
        http.Error(w, "Pastie not found", http.StatusNotFound)
        return
    }

    if pastie.PasswordHash != "" {
        // Show password prompt form if this is a GET request
        if r.Method == http.MethodGet {
            tmpl, err := template.ParseFiles("templates/password_prompt.html")
            if err != nil {
                http.Error(w, "Error loading password prompt template", http.StatusInternalServerError)
                return
            }
            tmpl.Execute(w, map[string]string{"PastieID": id})
            return
        }

        // For POST request, validate the provided password
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

    // Mark pastie as viewed if it is a view-once pastie
    if pastie.ViewOnce {
        pastie.Viewed = true
        db.Delete(&pastie)
    } else {
        db.Save(&pastie)
    }

    // Calculate time remaining
    var timeRemaining string
    if !pastie.ExpiresAt.IsZero() {
        duration := time.Until(pastie.ExpiresAt)
        timeRemaining = fmt.Sprintf("%02d:%02d:%02d remaining",
            int(duration.Hours()),
            int(duration.Minutes())%60,
            int(duration.Seconds())%60,
        )
    }

    tmpl, err := template.ParseFiles("templates/view_pastie.html")
    if err != nil {
        http.Error(w, "Error loading view pastie template", http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, map[string]interface{}{
        "Content":       decryptedContent,
        "TimeRemaining": timeRemaining,
    })
}

func generateID() string {
    b := make([]byte, 12) // Increase length for better security
    _, err := rand.Read(b)
    if err != nil {
        log.Errorf("Failed to generate random ID: %v", err)
    }
    return base64.URLEncoding.EncodeToString(b)
}

func generateSelfSignedCertificate(certPath, keyPath string) error {
    priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    if err != nil {
        return fmt.Errorf("failed to generate private key: %v", err)
    }

    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization: []string{"PastiePie Self-Signed"},
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(365 * 24 * time.Hour),

        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
    if err != nil {
        return fmt.Errorf("failed to create certificate: %v", err)
    }

    certFile, err := os.Create(certPath)
    if err != nil {
        return fmt.Errorf("failed to open cert.pem for writing: %v", err)
    }
    defer certFile.Close()

    pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

    keyFile, err := os.Create(keyPath)
    if err != nil {
        return fmt.Errorf("failed to open key.pem for writing: %v", err)
    }
    defer keyFile.Close()

    privBytes, err := x509.MarshalECPrivateKey(priv)
    if err != nil {
        return fmt.Errorf("failed to marshal private key: %v", err)
    }

    pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

    return nil
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

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
    target := "https://" + r.Host + r.URL.RequestURI()
    http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

func startExpiredPastiesCleanup(interval time.Duration) {
    ticker := time.NewTicker(interval)
    go func() {
        for range ticker.C {
            log.Info("Running expired pasties cleanup...")
            if err := db.Where("expires_at <= ?", time.Now()).Delete(&Pastie{}).Error; err != nil {
                log.Errorf("Failed to delete expired pasties: %v", err)
            }
        }
    }()
}
