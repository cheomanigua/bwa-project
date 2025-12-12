package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

// --- Configuration ---
var (
	StaticRoot  = getEnv("STATIC_ROOT", "public")
	ContentRoot = getEnv("CONTENT_ROOT", "../frontend/content/posts")

	GCSBucket   = getEnv("GCS_BUCKET", "content")
	GCSAccessID = getEnv("GCS_ACCESS_ID", "localhost")
)

// --- Domain Models ---

type UserRegistration struct {
	IDToken string `json:"idToken"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Plan    string `json:"plan"`
}

type AuthUser struct {
	UID          string
	Email        string
	Plan         string
	Name         string
	RegisteredAt time.Time
}

// --- Content Guard ---

type ContentGuard struct {
	permissions map[string][]string
	mu          sync.RWMutex
}

var contentGuard = ContentGuard{permissions: make(map[string][]string)}

var reFrontMatter = regexp.MustCompile(`(?s)^(?:---|\+\+\+)\s*[\r\n](.*?)[\r\n](?:---|\+\+\+)`)
var reCategories = regexp.MustCompile(`categories\s*[:=]\s*\[([^\]]+)]`)

func (cg *ContentGuard) Init() error {
	log.Println("Initializing Content Guard...")
	return filepath.Walk(ContentRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".md") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		fmMatch := reFrontMatter.FindSubmatch(content)
		if len(fmMatch) < 2 {
			return nil
		}

		catMatch := reCategories.FindStringSubmatch(string(fmMatch[1]))
		if len(catMatch) < 2 {
			return nil
		}

		rawPlans := strings.Split(catMatch[1], ",")
		var requiredPlans []string
		for _, p := range rawPlans {
			plan := strings.TrimSpace(strings.Trim(p, `'"`))
			if plan != "" {
				requiredPlans = append(requiredPlans, plan)
			}
		}

		if len(requiredPlans) > 0 {
			urlPath := strings.TrimPrefix(path, ContentRoot)
			urlPath = strings.TrimSuffix(urlPath, ".md")
			urlPath = strings.ReplaceAll(urlPath, string(filepath.Separator), "/")
			finalURLPath := "/posts" + urlPath
			finalURLPath = strings.TrimSuffix(finalURLPath, "/")
			finalURLPath = strings.TrimSuffix(finalURLPath, "/index")

			cg.mu.Lock()
			cg.permissions[finalURLPath] = requiredPlans
			cg.mu.Unlock()
			log.Printf("ContentGuard: %s requires plans: %v", finalURLPath, requiredPlans)
		}
		return nil
	})
}

func (cg *ContentGuard) IsAuthorized(path string, userPlan string) bool {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	requiredPlans, ok := cg.permissions[path]
	if !ok || len(requiredPlans) == 0 {
		return true
	}
	if userPlan == "visitor" {
		return false
	}
	return slices.Contains(requiredPlans, userPlan)
}

// --- Global Clients ---
var (
	authClient      *auth.Client
	firestoreClient *firestore.Client
	gcsClient       *storage.Client
)

func generateSignedURL(objectName string) (string, error) {
	isEmulator := os.Getenv("GCS_EMULATOR_HOST") != ""
	if !isEmulator {
		// Production path — keep your real signing logic
		opts := &storage.SignedURLOptions{
			Method:         "GET",
			Expires:        time.Now().Add(15 * time.Minute),
			Scheme:         storage.SigningSchemeV4,
			GoogleAccessID: GCSAccessID,
		}
		return gcsClient.Bucket(GCSBucket).SignedURL(objectName, opts)
	}

	// EMULATOR MODE: fake-gcs-server IGNORES signature → just build URL manually
	base := "http://localhost:5000"
	path := fmt.Sprintf("/gcs-content/%s/%s", GCSBucket, objectName)
	expires := time.Now().Add(15 * time.Minute).Unix()

	url := fmt.Sprintf("%s%s?X-Goog-Algorithm=GOOG4-RSA-SHA256"+
		"&X-Goog-Credential=%s%%2F%s%%2Fauto%%2Fstorage%%2Fgoog4_request"+
		"&X-Goog-Date=%s"+
		"&X-Goog-Expires=%d"+
		"&X-Goog-SignedHeaders=host",
		base, path,
		GCSAccessID,
		time.Now().Format("20060102"),
		time.Now().Format("20060102T150405Z"),
		int(expires-time.Now().Unix()),
	)

	log.Printf("Emulator mode: fake signed URL generated: %s", url)
	return url, nil
}

// --- Handlers ---
func contentGuardHandler(w http.ResponseWriter, r *http.Request) {
	user := getAuthenticatedUserFromCookie(r)
	userPlan := "visitor"
	if user != nil {
		userPlan = user.Plan
	}

	requestPath := strings.TrimSuffix(r.URL.Path, "/")
	requestPath = strings.TrimSuffix(requestPath, "/index.html")

	if !contentGuard.IsAuthorized(requestPath, userPlan) {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<!DOCTYPE html>
			<html><head><title>Access Denied</title></head>
			<body><h1>Access Denied</h1><p>You need a higher plan to view this content.</p></body>
			</html>
		`)
		return
	}

	// CORRECT: object name without bucket prefix
	objectPath := strings.TrimPrefix(requestPath, "/")   // "posts/week0001"
	objectPath = filepath.Join(objectPath, "index.html") // "posts/week0001/index.html"

	log.Printf("User authorized. Generating Signed URL for object: %s", objectPath)

	signedURL, err := generateSignedURL(objectPath)
	if err != nil {
		log.Printf("Failed to generate signed URL: %v", err)
		http.Error(w, "Failed to generate secure link", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, signedURL, http.StatusFound)
}

// --- API Endpoints ---
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reg UserRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	token, err := authClient.VerifyIDToken(r.Context(), reg.IDToken)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	_, err = firestoreClient.Collection("users").Doc(token.UID).Set(r.Context(), map[string]any{
		"plan":         reg.Plan,
		"name":         reg.Name,
		"email":        reg.Email,
		"registeredAt": firestore.ServerTimestamp,
	})
	if err != nil {
		http.Error(w, "Failed to save profile", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "registered"})
}

func handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDToken string `json:"idToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	cookie, err := authClient.SessionCookie(r.Context(), req.IDToken, 24*5*time.Hour)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "__session",
		Value:    cookie,
		MaxAge:   60 * 60 * 24 * 5,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "logged in"})
}

func handleSessionLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "__session",
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})
	w.WriteHeader(http.StatusOK)
}

func handleSession(w http.ResponseWriter, r *http.Request) {
	user := getAuthenticatedUserFromCookie(r)
	if user != nil {
		json.NewEncoder(w).Encode(map[string]any{
			"loggedIn": true,
			"plan":     user.Plan,
			"name":     user.Name,
			"email":    user.Email,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]any{"loggedIn": false, "plan": "visitor"})
	}
}

func getAuthenticatedUserFromCookie(r *http.Request) *AuthUser {
	cookie, err := r.Cookie("__session")
	if err != nil {
		return nil
	}
	token, err := authClient.VerifySessionCookie(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}

	userPlan := "basic"
	userName := ""
	if firestoreClient != nil {
		doc, _ := firestoreClient.Collection("users").Doc(token.UID).Get(r.Context())
		if doc.Exists() {
			data := doc.Data()
			if p, ok := data["plan"].(string); ok {
				userPlan = p
			}
			if n, ok := data["name"].(string); ok {
				userName = n
			}
		}
	}

	return &AuthUser{
		UID:   token.UID,
		Email: token.Claims["email"].(string),
		Plan:  userPlan,
		Name:  userName,
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- Main ---
func main() {
	ctx := context.Background()

	app, err := firebase.NewApp(ctx, &firebase.Config{ProjectID: "my-test-project"})
	if err != nil {
		log.Fatal(err)
	}

	authClient, err = app.Auth(ctx)
	if err != nil {
		log.Fatal(err)
	}
	firestoreClient, err = app.Firestore(ctx)
	if err != nil {
		log.Fatal(err)
	}

	var gcsOpts []option.ClientOption
	if host := os.Getenv("GCS_EMULATOR_HOST"); host != "" {
		gcsOpts = append(gcsOpts,
			option.WithEndpoint("http://"+host),
			option.WithoutAuthentication(),
		)
	}
	gcsClient, err = storage.NewClient(ctx, gcsOpts...)
	if err != nil {
		log.Fatal(err)
	}

	if err := contentGuard.Init(); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", contentGuardHandler)
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/sessionLogin", handleSessionLogin)
	http.HandleFunc("/api/sessionLogout", handleSessionLogout)
	http.HandleFunc("/api/session", handleSession)

	port := getEnv("PORT", "8081")
	log.Printf("Starting Go server on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
