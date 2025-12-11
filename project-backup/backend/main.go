package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	//"golang.org/x/crypto/bcrypt"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

// --- Configuration ---

var (
	// Use environment variables or fall back to local dev paths
	StaticRoot  = getEnv("STATIC_ROOT", "public")
	ContentRoot = getEnv("CONTENT_ROOT", "../frontend/content/posts")
)

// --- Domain Models ---

type UserRegistration struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Plan     string `json:"plan"`
	Name     string `json:"name"` // Matches the client-side payload
}

// AuthUser holds the necessary information after a successful session check
type AuthUser struct {
	UID   string
	Email string
	Plan  string // Fetched from Firestore
}

// --- Content Guard (Efficiency Upgrade) ---
// Indexes content permissions at startup so we don't parse files on every request.

type ContentGuard struct {
	// Map of URL path -> Required Categories/Plans
	permissions map[string][]string
	mu          sync.RWMutex
}

var authClient *auth.Client
var firestoreClient *firestore.Client

// --- Main ---

func main() {
	ctx := context.Background()

	authHost := os.Getenv("FIREBASE_AUTH_EMULATOR_HOST")
	if authHost == "" {
		log.Fatal("FIREBASE_AUTH_EMULATOR_HOST environment variable not set.")
	}
	log.Printf("Using Firebase Auth Emulator Host: %s\n", authHost)

	firestoreHost := os.Getenv("FIRESTORE_EMULATOR_HOST")
	if firestoreHost == "" {
		log.Fatal("FIRESTORE_EMULATOR_HOST environment variable not set.")
	}
	log.Printf("Using Firestore Emulator Host: %s\n", firestoreHost)

	conf := &firebase.Config{ProjectID: "my-test-project"}

	app, err := firebase.NewApp(ctx, conf,
		option.WithoutAuthentication(),
		option.WithGRPCConnectionPool(1),
	)

	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	authClient, err = app.Auth(ctx)
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}
	log.Println("Firebase Admin Auth Client initialized successfully.")

	firestoreClient, err = app.Firestore(ctx)
	if err != nil {
		log.Fatalf("error getting Firestore client: %v\n", err)
	}
	log.Println("Firebase Firestore Client initialized successfully.")

	//*********************************************//
	// Initialize Logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	server := NewServer()

	slog.Info("Server starting", "port", 8081)
	if err := http.ListenAndServe("0.0.0.0:8081", server.routes()); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}

//**********************************************//

func setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
}

func sendJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// ******************************************//
// getEnv reads an environment variable or returns a fallback
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
func NewContentGuard() *ContentGuard {
	slog.Info("ContentRoot", "path", ContentRoot) /////// TEST TEST TEST TEST TEST /////////
	cg := &ContentGuard{
		permissions: make(map[string][]string),
	}
	if err := cg.IndexContent(); err != nil {
		slog.Warn("Failed to index initial content", "error", err)
	}
	return cg
}

func (cg *ContentGuard) IndexContent() error {
	slog.Info("Indexing content permissions...")
	newPerms := make(map[string][]string)

	// Regex to extract categories from Front Matter
	// Supports TOML (+++) and YAML (---)
	reFrontMatter := regexp.MustCompile(`(?s)^(?:---|\+\+\+)\s*[\r\n](.*?)[\r\n](?:---|\+\+\+)`)
	reCategories := regexp.MustCompile(`categories\s*[:=]\s*\[([^\]]+)]`)

	err := filepath.Walk(ContentRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}

		// Calculate URL path from file path
		rel, _ := filepath.Rel(ContentRoot, path)
		urlPath := "/posts/" + strings.TrimSuffix(rel, ".md")
		urlPath = strings.TrimSuffix(urlPath, "/index")

		// Read File
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Parse Front Matter
		matches := reFrontMatter.FindSubmatch(data)
		if len(matches) < 2 {
			return nil
		}

		// Extract Categories
		catMatches := reCategories.FindStringSubmatch(string(matches[1]))
		if len(catMatches) > 1 {
			parts := strings.Split(catMatches[1], ",")
			var cats []string
			for _, p := range parts {
				c := strings.TrimSpace(strings.Trim(p, `'" `))
				if c != "" {
					cats = append(cats, strings.ToLower(c))
				}
			}
			newPerms[urlPath] = cats
			// Also map the directory if it's an index file
			if !strings.HasSuffix(urlPath, "/") {
				newPerms[urlPath+"/"] = cats
			}
		}
		return nil
	})

	cg.mu.Lock()
	cg.permissions = newPerms
	cg.mu.Unlock()
	return err
}

func (cg *ContentGuard) CanAccess(urlPath, userPlan string) bool {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	// Normalize path
	cleanPath := strings.TrimSuffix(urlPath, "/")

	// Check exact match or match with slash
	reqPlans, ok := cg.permissions[cleanPath]
	if !ok {
		reqPlans, ok = cg.permissions[urlPath]
	}

	// If content is not tracked in permissions, assume public or handle 404 elsewhere
	if !ok {
		// If it starts with /posts but we didn't find it in index, it might not exist
		// or it has no categories. Let's assume restricted if not found but in protected dir.
		return false
	}

	for _, p := range reqPlans {
		if p == strings.ToLower(userPlan) {
			return true
		}
	}
	return false
}

// --- Server & Handlers ---

type Server struct {
	content *ContentGuard
	hugoFS  http.Handler
}

func NewServer() *Server {
	return &Server{
		content: NewContentGuard(),
		hugoFS:  http.FileServer(http.Dir(StaticRoot)),
	}
}

// *** REFATORING FOR CADDY ***
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// API Diagnostics - ADDED FOR TESTING
	mux.HandleFunc("/api/status", statusHandler)

	// Auth Routes - CADDY STRIPS /api, so the path is only the endpoint name.
	// We use NO trailing slash for exact path matching of API calls.
	mux.HandleFunc("/api/register", registerHandler)
	mux.HandleFunc("/api/session", s.handleAPISession)

	// Public Assets
	mux.Handle("/css/", s.hugoFS)
	mux.Handle("/js/", s.hugoFS)
	mux.Handle("/images/", s.hugoFS)
	mux.Handle("/fonts/", s.hugoFS)
	mux.Handle("/favicon.ico", s.hugoFS)

	// Matches anything not caught above
	mux.HandleFunc("/", s.handleContent)

	return s.logMiddleware(mux)
}

// --- Handler Implementations ---

// statusHandler is a simple diagnostic endpoint.
func statusHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, r)
	if r.Method != http.MethodGet {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "Go API is running and ready for traffic.",
	})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("DEBUG: Reached registerHandler. Starting payload decode...")
	setCORSHeaders(w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds UserRegistration
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		sendJSONError(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	params := (&auth.UserToCreate{}).
		Email(creds.Email).
		Password(creds.Password)

	userRecord, err := authClient.CreateUser(r.Context(), params)
	if err != nil {
		log.Printf("Failed to create user: %v\n", err)
		sendJSONError(w, fmt.Sprintf("Registration failed: %v", err), http.StatusInternalServerError)
		return
	}

	userProfile := map[string]interface{}{
		"email":         creds.Email,
		"registered_at": firestore.ServerTimestamp,
		"name":          creds.Name,
		"rol":           "User",
		"plan":          creds.Plan,
	}

	_, err = firestoreClient.Collection("users").Doc(userRecord.UID).Set(r.Context(), userProfile)
	if err != nil {
		log.Printf("Warning: Failed to save user profile to Firestore: %v\n", err)
	} else {
		log.Printf("User profile saved to Firestore under UID: %s\n", userRecord.UID)
	}

	log.Printf("Successfully created new user: %s (UID: %s)\n", userRecord.Email, userRecord.UID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("User %s registered successfully (Auth and Profile Saved).", userRecord.Email),
		"email":   userRecord.Email,
		"uid":     userRecord.UID,
	})
}

// --- Handler Implementations (REPLACED handleAPISession) ---

func (s *Server) handleAPISession(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, r)
	w.Header().Set("Content-Type", "application/json")

	// Handle CORS preflight request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// REPLACED: _, user := s.auth.GetSession(w, r)
	// Uses the new helper that verifies the Firebase Session Cookie
	user := getAuthenticatedUserFromCookie(r)

	if user == nil {
		// User is not authenticated or session is invalid/expired
		w.WriteHeader(http.StatusOK) // Often returns 200 OK to indicate the check was successful, but the user is logged out
		w.Write([]byte(`{"loggedIn": false}`))
		return
	}

	// Session is valid. Return user details.
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"loggedIn": true,
		"email":    user.Email, // Requires AuthUser struct to be updated with Email
		"plan":     user.Plan,
	})
}

// --- Handler Implementations (REPLACED handleContent) ---

func (s *Server) handleContent(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Serve home immediately
	if path == "/" {
		// We still need to serve the home page, usually index.html
		http.ServeFile(w, r, filepath.Join(StaticRoot, "index.html"))
		return
	}

	// Check protected paths
	protectedPrefixes := []string{"/posts", "/account", "/tags", "/categories"}
	isProtected := false
	for _, prefix := range protectedPrefixes {
		if strings.HasPrefix(path, prefix) {
			isProtected = true
			break
		}
	}

	if !isProtected {
		// Serve standard static files (about, contact, etc)
		s.hugoFS.ServeHTTP(w, r)
		return
	}

	// 1. Check Authentication (REPLACED s.auth.GetSession)
	user := getAuthenticatedUserFromCookie(r)
	if user == nil {
		// Redirect to the static login page, preserving the intended destination path
		// We must use url.QueryEscape to handle paths with special characters
		http.Redirect(w, r, "/login?next="+url.QueryEscape(path), http.StatusSeeOther)
		return
	}

	// 2. Check Authorization (Plan vs Content)
	if strings.HasPrefix(path, "/posts") {
		// Check for specific post pages, skipping listing and pagination pages
		if path != "/posts" && path != "/posts/" && !strings.Contains(path, "/page/") {
			// Use the Plan fetched from Firestore (user.Plan)
			if allowed := s.content.CanAccess(path, user.Plan); !allowed {
				http.Redirect(w, r, "/dashboard?error=upgrade_required", http.StatusSeeOther)
				return
			}
		}
	}

	// 3. Serve Protected File
	w.Header().Set("Cache-Control", "no-store") // Don't cache protected content in browser
	s.hugoFS.ServeHTTP(w, r)
}

// --- Helpers & Middleware ---

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 🛑 GUARANTEED LOG: Log the request immediately upon entry
		slog.Info("Request received",
			"method", r.Method,
			"path", r.URL.Path)

		next.ServeHTTP(w, r)

		// Log the completion/duration after the handler runs
		slog.Info("Request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start))
	})
}

// getAuthenticatedUserFromCookie verifies the Firebase Session Cookie and fetches the user's plan.
// Note: This relies on the client successfully exchanging the ID Token for a Session Cookie
// and sending that cookie back with subsequent requests.
// getAuthenticatedUserFromCookie verifies the Firebase Session Cookie and fetches the user's plan.
func getAuthenticatedUserFromCookie(r *http.Request) *AuthUser {
	// 1. Read the Firebase Session Cookie
	cookie, err := r.Cookie("__session")
	if err != nil {
		return nil // No cookie found, user is unauthenticated
	}

	// 2. Verify the Session Cookie
	token, err := authClient.VerifySessionCookie(r.Context(), cookie.Value)
	if err != nil {
		log.Printf("Session cookie verification failed: %v", err)
		return nil
	}

	// 3. Extract Email from token claims (Definition of userEmail)
	userEmail, ok := token.Claims["email"].(string)
	if !ok {
		log.Printf("Warning: Email claim missing from Firebase token for UID: %s", token.UID)
		userEmail = ""
	}

	// 4. Fetch custom plan data from Firestore
	userPlan := "basic" // Definition of userPlan

	dsnap, err := firestoreClient.Collection("users").Doc(token.UID).Get(r.Context())
	if err == nil && dsnap.Exists() {
		if p, found := dsnap.Data()["plan"].(string); found {
			userPlan = p
		}
	} else if err != nil {
		log.Printf("Warning: Failed to fetch user profile for %s from Firestore: %v", token.UID, err)
	}

	// 5. Return the populated struct (Usage of userEmail)
	return &AuthUser{
		UID:   token.UID,
		Email: userEmail, // <-- Use the variable defined in step 3
		Plan:  userPlan,
	}
}
