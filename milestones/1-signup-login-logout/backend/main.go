package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
)

var (
	// Use environment variables or fall back to local dev paths
	StaticRoot  = getEnv("STATIC_ROOT", "public")
	ContentRoot = getEnv("CONTENT_ROOT", "../frontend/content/posts")
)

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

var authClient *auth.Client
var firestoreClient *firestore.Client

// getEnv reads an environment variable or returns a fallback
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// --- Server & Handlers ---

type Server struct {
	hugoFS http.Handler
}

func NewServer() *Server {
	return &Server{
		hugoFS: http.FileServer(http.Dir(StaticRoot)),
	}
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
