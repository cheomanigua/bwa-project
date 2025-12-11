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
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
)

// --- Configuration ---

var (
	// Use environment variables or fall back to local dev paths
	StaticRoot  = getEnv("STATIC_ROOT", "public")
	ContentRoot = getEnv("CONTENT_ROOT", "../frontend/content/posts")
)

// --- Domain Models ---

type UserRegistration struct {
	IDToken string `json:"idToken"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Plan    string `json:"plan"`
}

// AuthUser holds the necessary information after a successful session check
type AuthUser struct {
	UID          string
	Email        string
	Plan         string // Fetched from Firestore
	Name         string
	RegisteredAt time.Time
}

// --- Content Guard (Plan Matching Logic) ---

type ContentGuard struct {
	// Map of URL path -> Required Categories/Plans
	// Example: "/posts/week0001" -> ["basic", "pro"]
	permissions map[string][]string
	mu          sync.RWMutex
}

var contentGuard = ContentGuard{permissions: make(map[string][]string)}

// Regex definitions for front matter parsing (using your suggested patterns)
var reFrontMatter = regexp.MustCompile(`(?s)^(?:---|\+\+\+)\s*[\r\n](.*?)[\r\n](?:---|\+\+\+)`)
var reCategories = regexp.MustCompile(`categories\s*[:=]\s*\[([^\]]+)]`)

// Init loads permissions from the front matter of all Markdown files.
func (cg *ContentGuard) Init() error {
	log.Println("Initializing Content Guard...")

	// Walk the content directory
	return filepath.Walk(ContentRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".md") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// 1. Extract the front matter block
		fmMatch := reFrontMatter.FindSubmatch(content)
		if len(fmMatch) < 2 {
			return nil // No front matter found
		}
		frontMatterBlock := string(fmMatch[1]) // Content between delimiters

		// 2. Extract the categories array string (e.g., 'basic','pro')
		catMatch := reCategories.FindStringSubmatch(frontMatterBlock)
		if len(catMatch) < 2 {
			return nil // No 'categories' field found
		}
		rawCategoriesStr := catMatch[1]

		// 3. Manually parse the raw string into a slice of strings
		rawPlans := strings.Split(rawCategoriesStr, ",")
		var requiredPlans []string
		for _, p := range rawPlans {
			// Trim whitespace and quotes from each plan string
			plan := strings.TrimSpace(p)
			plan = strings.Trim(plan, `'"`)
			if plan != "" {
				requiredPlans = append(requiredPlans, plan)
			}
		}

		if len(requiredPlans) > 0 {
			// Convert filesystem path to URL path (e.g., /posts/week0001)
			urlPath := strings.TrimPrefix(path, ContentRoot)
			urlPath = strings.TrimSuffix(urlPath, ".md")
			urlPath = strings.ReplaceAll(urlPath, string(filepath.Separator), "/")

			// The final key must match the request URL, e.g., /posts/week0001
			finalURLPath := "/posts" + urlPath
			finalURLPath = strings.TrimSuffix(finalURLPath, "/")
			finalURLPath = strings.TrimSuffix(finalURLPath, "/index") // Clean up index.md

			cg.mu.Lock()
			cg.permissions[finalURLPath] = requiredPlans
			cg.mu.Unlock()
			log.Printf("ContentGuard: %s requires plans: %v", finalURLPath, requiredPlans)
		}
		return nil
	})
}

// IsAuthorized checks if the user's plan matches any of the required categories for the path.
func (cg *ContentGuard) IsAuthorized(path string, userPlan string) bool {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	requiredPlans, ok := cg.permissions[path]

	if !ok || len(requiredPlans) == 0 {
		// Content is not restricted (accessible by all)
		return true
	}

	// Content IS restricted.

	// If unauthenticated, access is denied.
	if userPlan == "visitor" {
		return false
	}

	// Check if the authenticated user's plan matches any required category
	return slices.Contains(requiredPlans, userPlan)
}

// --- Global Clients ---

var authClient *auth.Client
var firestoreClient *firestore.Client

// --- Handlers (Content Guard) ---

// Handles requests to /posts/*, checking user plan against post category
func contentGuardHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Get AuthUser (which includes the plan). Plan will be "visitor" if unauthenticated.
	user := getAuthenticatedUserFromCookie(r)

	userPlan := "visitor"
	if user != nil {
		userPlan = user.Plan
	}

	// 2. Normalize the request path to match the stored ContentGuard keys
	requestPath := r.URL.Path

	// Remove trailing slash if present (e.g., /posts/week0001/ -> /posts/week0001)
	requestPath = strings.TrimSuffix(requestPath, "/")

	// Handle Hugo's index.html mapping: If the request is for /posts/week0001/index.html,
	// we still want the key /posts/week0001.
	requestPath = strings.TrimSuffix(requestPath, "/index.html")

	// 3. Check authorization
	if !contentGuard.IsAuthorized(requestPath, userPlan) {
		// Unauthorized
		log.Printf("Access Denied: User plan %s blocked for path %s", userPlan, requestPath)

		// Render a simple access denied message
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
            <!DOCTYPE html>
            <html>
            <head><title>Access Denied</title>
            <link rel="stylesheet" href="https://unpkg.com/tachyons@4.12.0/css/tachyons.min.css">
            </head>
            <body class="bg-light-gray">
                <div class="mw6 center ph3 pv5">
                    <h1 class="f2 red">Access Denied 🔒</h1>
                    <p class="f5 dark-gray">The content at <strong>%s</strong> requires a specific subscription plan.</p>
                    <p class="f5 dark-gray">Your current plan is <strong>%s</strong>.</p>
                    <a href="/" class="f6 link dim br2 ph3 pv2 mb2 dib white bg-blue">Upgrade Your Plan</a>
                </div>
            </body>
            </html>
        `, requestPath, userPlan)
		return
	}

	// 4. If authorized, serve the corresponding static file from Hugo's public directory.
	// Maps URL path (/posts/week0001) to file path (public/posts/week0001/index.html)
	staticFilePath := filepath.Join(StaticRoot, requestPath, "index.html")

	http.ServeFile(w, r, staticFilePath)
}

// --- Handlers (API) ---

// handleRegister handles the second stage of registration: verifying the user and
// storing their profile in Firestore.
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var userReg UserRegistration
	if err := json.NewDecoder(r.Body).Decode(&userReg); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1. Verify the ID Token to get the user's UID
	token, err := authClient.VerifyIDToken(r.Context(), userReg.IDToken)
	if err != nil {
		log.Printf("ID Token verification failed: %v", err)
		// Return 401 Unauthorized if the token is invalid
		http.Error(w, "Invalid ID Token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	userUID := token.UID

	// 2. Store user plan and name in Firestore
	userProfile := map[string]interface{}{
		"plan":  userReg.Plan,
		"name":  userReg.Name,
		"email": userReg.Email,
		// Optional: save a timestamp
		"registeredAt": firestore.ServerTimestamp,
	}

	_, err = firestoreClient.Collection("users").Doc(userUID).Set(r.Context(), userProfile)
	if err != nil {
		// Log the error and return a 500 error, as Firestore is critical for the plan
		log.Printf("Firestore set user profile failed for UID %s: %v", userUID, err)
		http.Error(w, "Registration failed: Could not save user plan.", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK) // Use 200 OK for a successful profile update
	json.NewEncoder(w).Encode(map[string]string{"uid": userUID, "message": "User profile saved successfully"})
}

// handleSessionLogin exchanges the Firebase ID Token for a secure session cookie.
func handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IDToken string `json:"idToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Set session expiration to 5 days
	expiresIn := time.Hour * 24 * 5

	// Create the session cookie
	cookie, err := authClient.SessionCookie(r.Context(), req.IDToken, expiresIn)
	if err != nil {
		log.Printf("Failed to create session cookie: %v", err)
		http.Error(w, "Failed to create session cookie", http.StatusInternalServerError)
		return
	}

	// Set the session cookie on the client
	http.SetCookie(w, &http.Cookie{
		Name:     "__session",
		Value:    cookie,
		MaxAge:   int(expiresIn.Seconds()),
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Session cookie set successfully"})
}

// handleSessionLogout clears the session cookie.
func handleSessionLogout(w http.ResponseWriter, r *http.Request) {
	// Clear the session cookie by setting MaxAge to a negative value
	http.SetCookie(w, &http.Cookie{
		Name:     "__session",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// handleSession checks if a user is logged in via the session cookie and returns their full profile.
func handleSession(w http.ResponseWriter, r *http.Request) {
	user := getAuthenticatedUserFromCookie(r)

	if user != nil {
		registeredAtStr := ""
		if !user.RegisteredAt.IsZero() {
			// Format the time as a simple date string, e.g., "Jan 2, 2006"
			registeredAtStr = user.RegisteredAt.Format("Jan 2, 2006")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"loggedIn":     true,
			"plan":         user.Plan,
			"email":        user.Email,
			"name":         user.Name,       // Added for dashboard
			"registeredAt": registeredAtStr, // Added for dashboard
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"loggedIn": false,
		"plan":     "visitor",
	})
}

// --- Helper Functions ---

// getEnv retrieves environment variable or returns a default value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// getAuthenticatedUserFromCookie checks the request for a valid session cookie,
// verifies it with Firebase Auth, and fetches the full user profile from Firestore.
func getAuthenticatedUserFromCookie(r *http.Request) *AuthUser {
	// 1. Check for the session cookie
	cookie, err := r.Cookie("__session")
	if err != nil {
		// Cookie not found (user is not logged in or session expired)
		return nil
	}

	// 2. Verify the Session Cookie
	// The authClient must be initialized in the main function.
	token, err := authClient.VerifySessionCookie(r.Context(), cookie.Value)
	if err != nil {
		log.Printf("Session cookie verification failed: %v", err)
		return nil
	}

	// 3. Extract Email from token claims
	userEmail, ok := token.Claims["email"].(string)
	if !ok {
		log.Printf("Warning: Email claim missing from Firebase token for UID: %s", token.UID)
		userEmail = ""
	}

	// 4. Fetch custom plan, name, and registeredAt data from Firestore
	userPlan := "basic" // Default plan in case Firestore fetch fails
	userName := ""
	var registeredAt time.Time // Initialize registration time to Zero value

	// firestoreClient must be initialized in main()
	if firestoreClient != nil {
		dsnap, err := firestoreClient.Collection("users").Doc(token.UID).Get(r.Context())
		if err == nil && dsnap.Exists() {
			data := dsnap.Data()
			if p, found := data["plan"].(string); found {
				userPlan = p
			}
			if n, found := data["name"].(string); found {
				userName = n // RETRIEVE NAME
			}
			// Firestore's ServerTimestamp maps to time.Time in Go
			if ts, found := data["registeredAt"].(time.Time); found {
				registeredAt = ts // RETRIEVE TIMESTAMP
			}
		} else if err != nil {
			log.Printf("Warning: Failed to fetch user profile for %s from Firestore: %v", token.UID, err)
		}
	}

	// 5. Return the full AuthUser profile
	return &AuthUser{
		UID:          token.UID,
		Email:        userEmail,
		Plan:         userPlan,
		Name:         userName,
		RegisteredAt: registeredAt,
	}
}

// --- Main Function ---

func main() {
	// Initialize Firebase Admin SDK
	ctx := context.Background()
	app, err := firebase.NewApp(ctx, &firebase.Config{
		ProjectID: "my-test-project",
	})
	if err != nil {
		log.Fatalf("error initializing firebase app: %v", err)
	}

	// Initialize Firebase Auth Client
	authClient, err = app.Auth(ctx)
	if err != nil {
		log.Fatalf("error getting auth client: %v", err)
	}

	// Initialize Firestore Client
	firestoreClient, err = app.Firestore(ctx)
	if err != nil {
		log.Fatalf("error getting firestore client: %v", err)
	}

	// --- Content Guard Initialization ---
	if err := contentGuard.Init(); err != nil {
		log.Fatalf("Failed to initialize ContentGuard: %v", err)
	}

	// --- Handler Registration ---

	// Content Handler (NEW)
	http.HandleFunc("/", contentGuardHandler)
	//http.HandleFunc("/posts/", contentGuardHandler)

	// API Handlers (Existing)
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/sessionLogin", handleSessionLogin)
	http.HandleFunc("/api/sessionLogout", handleSessionLogout)
	http.HandleFunc("/api/session", handleSession)

	// Start Server
	port := getEnv("PORT", "8081")
	log.Printf("Starting Go server on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
