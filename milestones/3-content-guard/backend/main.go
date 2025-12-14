package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
			Expires:        time.Now().Add(30 * time.Second),
			Scheme:         storage.SigningSchemeV4,
			GoogleAccessID: GCSAccessID,
		}
		return gcsClient.Bucket(GCSBucket).SignedURL(objectName, opts)
	}

	// EMULATOR MODE: fake-gcs-server IGNORES signature → just build URL manually
	base := "http://caddy-server:5000"
	path := fmt.Sprintf("/gcs-content/%s/%s", GCSBucket, objectName)
	fakeExpireLocalLinux := time.Now().Add(5 * time.Second).Unix()

	url := fmt.Sprintf("%s%s?X-Goog-Algorithm=GOOG4-RSA-SHA256"+
		"&X-Goog-Credential=%s%%2F%s%%2Fauto%%2Fstorage%%2Fgoog4_request"+
		"&X-Goog-Date=%s"+
		"&X-Goog-Expires=%d"+
		"&X-Goog-SignedHeaders=host",
		base, path,
		GCSAccessID,
		time.Now().Format("20060102"),
		time.Now().Format("20060102T150405Z"),
		int(fakeExpireLocalLinux-time.Now().Unix()),
	)

	log.Printf("Emulator mode: fake signed URL generated: %s", url)
	return url, nil
}

// --- HTTP Handlers ---

func handleContentGuard(w http.ResponseWriter, r *http.Request) {
	user := getAuthenticatedUserFromCookie(r)
	userPlan := "visitor"
	if user != nil {
		userPlan = user.Plan
	}

	requestPath := r.URL.Path
	requestPath = strings.TrimSuffix(requestPath, "/")
	requestPath = strings.TrimSuffix(requestPath, "/index.html")
	requestPath = strings.TrimSuffix(requestPath, "/index")

	// 1. Authorization Check
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

	// 2. Object Path Construction

	objectPath := strings.TrimPrefix(requestPath, "/")
	objectPath = filepath.Join(objectPath, "index.html")

	log.Printf("User authorized. Generating Signed URL for object: %s", objectPath)

	// 3. Generate Signed URL (Short-lived, server-side only)
	signedURL, err := generateSignedURL(objectPath)
	if err != nil {
		log.Printf("Failed to generate signed URL: %v", err)
		http.Error(w, "Failed to generate secure link", http.StatusInternalServerError)
		return
	}

	// 4. PROXY THE CONTENT from GCS

	// Create a new HTTP request to the GCS signed URL
	resp, err := http.Get(signedURL)
	if err != nil {
		log.Printf("Failed to fetch content from GCS: %v", err)
		http.Error(w, "Content fetch error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Handle GCS errors (e.g., object not found, or internal GCS error)
	if resp.StatusCode != http.StatusOK {
		log.Printf("GCS responded with status: %d for object: %s", resp.StatusCode, objectPath)
		// Propagate the error status back to the client
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	// 5. Set Response Headers

	// Copy original Content-Type from GCS
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	// CRITICAL: Set Cache-Control to prevent the client from caching the response.
	// This ensures that on refresh, the client *must* hit the server again,
	// which means the authorization logic runs again.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")

	// 6. Copy the Content to the Client

	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		// Note: Error here means write failure after headers were sent (client disconnect)
		log.Printf("Error copying content to client: %v", err)
	}
}

// --- API Handlers ---
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
	userProfile := map[string]any{
		"plan":         userReg.Plan,
		"name":         userReg.Name,
		"email":        userReg.Email,
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

	http.HandleFunc("/posts/", handleContentGuard)
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/sessionLogin", handleSessionLogin)
	http.HandleFunc("/api/sessionLogout", handleSessionLogout)
	http.HandleFunc("/api/session", handleSession)

	port := getEnv("PORT", "8081")
	log.Printf("Starting Go server on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
