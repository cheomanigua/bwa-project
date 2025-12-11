package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// --- Configuration ---

var (
	// Use environment variables or fall back to local dev paths
	StaticRoot  = getEnv("STATIC_ROOT", "public")
	ContentRoot = getEnv("CONTENT_ROOT", "../frontend/content/posts")
	UsersFile   = getEnv("USERS_FILE", "users.db")
	SessionFile = getEnv("SESSION_FILE", "sessions/sessions.json")
)

//const (
//	UsersFile     = "users.db" // Changed extension to imply structured data
//	SessionFile   = "sessions/sessions.json"
//	StaticRoot    = "public"
//	ContentRoot   = "../frontend/content/posts" // Adjust based on your actual structure
//	SessionExpiry = 24 * time.Hour
//)

const (
	SessionExpiry = 24 * time.Hour
)

// --- Domain Models ---

type User struct {
	Email        string `json:"email"`
	PasswordHash string `json:"-"` // Never serialize password
	Plan         string `json:"plan"`
}

type Session struct {
	ID        string    `json:"id"`
	UserEmail string    `json:"user_email"`
	Expiry    time.Time `json:"expiry"`
}

// --- Content Guard (Efficiency Upgrade) ---
// Indexes content permissions at startup so we don't parse files on every request.

type ContentGuard struct {
	// Map of URL path -> Required Categories/Plans
	permissions map[string][]string
	mu          sync.RWMutex
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

// --- Auth Service (Security Upgrade) ---

type AuthService struct {
	users    map[string]User
	sessions map[string]Session
	userMu   sync.RWMutex
	sessMu   sync.RWMutex
}

func NewAuthService() *AuthService {
	as := &AuthService{
		users:    make(map[string]User),
		sessions: make(map[string]Session),
	}
	as.loadUsers()
	as.loadSessions()

	// Periodic cleanup
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		for range ticker.C {
			as.cleanupSessions()
		}
	}()

	return as
}

func (as *AuthService) Register(email, password, plan string) error {
	as.userMu.Lock()
	defer as.userMu.Unlock()

	if _, exists := as.users[email]; exists {
		return errors.New("user already exists")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u := User{Email: email, PasswordHash: string(hash), Plan: plan}
	as.users[email] = u
	return as.saveUserAppend(u)
}

func (as *AuthService) Login(email, password string) (*Session, error) {
	as.userMu.RLock()
	user, ok := as.users[email]
	as.userMu.RUnlock()

	if !ok {
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Create Session
	sid, _ := generateRandomString(32)
	sess := Session{
		ID:        sid,
		UserEmail: email,
		Expiry:    time.Now().Add(SessionExpiry),
	}

	as.sessMu.Lock()
	as.sessions[sid] = sess
	as.sessMu.Unlock()

	// Persist asynchronously or simplified periodic save
	go as.saveSessions()

	return &sess, nil
}

func (as *AuthService) GetSession(w http.ResponseWriter, r *http.Request) (*Session, *User) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil, nil
	}

	as.sessMu.RLock()
	sess, ok := as.sessions[cookie.Value]
	as.sessMu.RUnlock()

	if !ok || time.Now().After(sess.Expiry) {
		return nil, nil
	}

	// Auto-refresh session
	if time.Until(sess.Expiry) < 12*time.Hour {
		as.sessMu.Lock()
		sess.Expiry = time.Now().Add(SessionExpiry)
		as.sessions[cookie.Value] = sess
		as.sessMu.Unlock()
		http.SetCookie(w, makeCookie(sess.ID, sess.Expiry))
		go as.saveSessions()
	}

	as.userMu.RLock()
	user, userOk := as.users[sess.UserEmail]
	as.userMu.RUnlock()

	if !userOk {
		return nil, nil
	}

	return &sess, &user
}

func (as *AuthService) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		as.sessMu.Lock()
		delete(as.sessions, cookie.Value)
		as.sessMu.Unlock()
		go as.saveSessions()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// --- Persistence Helpers ---

func (as *AuthService) loadUsers() {
	f, err := os.Open(UsersFile)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Error("Failed to load users", "error", err)
		}
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "|") // using | as delimiter
		if len(parts) == 3 {
			as.users[parts[0]] = User{Email: parts[0], PasswordHash: parts[1], Plan: parts[2]}
		}
	}
}

func (as *AuthService) saveUserAppend(u User) error {
	f, err := os.OpenFile(UsersFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	// Format: email|hash|plan
	_, err = fmt.Fprintf(f, "%s|%s|%s\n", u.Email, u.PasswordHash, u.Plan)
	return err
}

func (as *AuthService) loadSessions() {
	f, err := os.Open(SessionFile)
	if err == nil {
		defer f.Close()
		json.NewDecoder(f).Decode(&as.sessions)
	}
}

func (as *AuthService) saveSessions() {
	as.sessMu.RLock()
	defer as.sessMu.RUnlock()

	os.MkdirAll(filepath.Dir(SessionFile), 0o700)
	f, err := os.Create(SessionFile)
	if err != nil {
		slog.Error("Failed to save sessions", "error", err)
		return
	}
	defer f.Close()
	json.NewEncoder(f).Encode(as.sessions)
}

func (as *AuthService) cleanupSessions() {
	now := time.Now()
	as.sessMu.Lock()
	for id, s := range as.sessions {
		if now.After(s.Expiry) {
			delete(as.sessions, id)
		}
	}
	as.sessMu.Unlock()
	as.saveSessions()
}

// --- Server & Handlers ---

type Server struct {
	auth    *AuthService
	content *ContentGuard
	hugoFS  http.Handler
}

func NewServer() *Server {
	return &Server{
		auth:    NewAuthService(),
		content: NewContentGuard(),
		hugoFS:  http.FileServer(http.Dir(StaticRoot)),
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Public Assets
	mux.Handle("/css/", s.hugoFS)
	mux.Handle("/js/", s.hugoFS)
	mux.Handle("/images/", s.hugoFS)
	mux.Handle("/fonts/", s.hugoFS)
	mux.Handle("/favicon.ico", s.hugoFS)

	// Auth Routes
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/register", s.handleRegister)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/session", s.handleAPISession)

	// Protected Routes (Content)
	// Matches anything not caught above
	mux.HandleFunc("/", s.handleContent)

	return s.logMiddleware(mux)
}

// --- Handler Implementations ---

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		pass := r.FormValue("password")

		sess, err := s.auth.Login(email, pass)
		if err != nil {
			http.Redirect(w, r, "/api/login?error=invalid", http.StatusSeeOther)
			return
		}

		http.SetCookie(w, makeCookie(sess.ID, sess.Expiry))
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.serveStaticOrFallback(w, r, "login/index.html")
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		pass := r.FormValue("password")
		plan := strings.ToLower(r.FormValue("plan"))
		if plan == "" {
			plan = "basic"
		}

		if err := s.auth.Register(email, pass, plan); err != nil {
			slog.Error("Register failed", "error", err)
			http.Error(w, "Registration failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/api/login?registered=1", http.StatusSeeOther)
		return
	}
	s.serveStaticOrFallback(w, r, "register/index.html")
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.Logout(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleAPISession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, user := s.auth.GetSession(w, r)
	if user == nil {
		w.Write([]byte(`{"loggedIn": false}`))
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"loggedIn": true,
		"email":    user.Email,
		"plan":     user.Plan,
	})
}

func (s *Server) handleContent(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Serve home immediately
	if path == "/" {
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

	// 1. Check Authentication
	sess, user := s.auth.GetSession(w, r)
	if sess == nil {
		http.Redirect(w, r, "/api/login?next="+path, http.StatusSeeOther)
		return
	}

	// 2. Check Authorization (Plan vs Content)
	if strings.HasPrefix(path, "/posts") {
		// Skip plan check for the listing page itself if desired,
		// or implement specific logic. Here we check specific posts.
		if path != "/posts" && path != "/posts/" && !strings.Contains(path, "/page/") {
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

func (s *Server) serveStaticOrFallback(w http.ResponseWriter, r *http.Request, fallbackFile string) {
	// Try serving from URL path first (standard Hugo behavior)
	fullPath := filepath.Join(StaticRoot, r.URL.Path)
	if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
		http.ServeFile(w, r, fullPath)
		return
	}
	// Serve the logic-based fallback (e.g. login.html)
	http.ServeFile(w, r, filepath.Join(StaticRoot, fallbackFile))
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Info("Request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start))
	})
}

func makeCookie(id string, expiry time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     "session_id",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		Expires:  expiry,
	}
}

func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := cryptRandInt(len(letters))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num]
	}
	return string(ret), nil
}

func cryptRandInt(max int) (int, error) {
	b := make([]byte, 1)
	if _, err := idsRandRead(b); err != nil {
		return 0, err
	}
	return int(b[0]) % max, nil
}

// wrapper to mock in tests if needed, pointing to crypto/rand
var idsRandRead = func(b []byte) (int, error) {
	// Using the crypto/rand from stdlib, aliased or imported directly
	// Here we assume "crypto/rand" is imported as rand (aliased) or just use raw
	// Since we didn't alias it in imports, let's do it manually via the existing import
	// Note: imports list needs "crypto/rand"
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Read(b)
}

// --- Main ---

func main() {
	// Initialize Logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	server := NewServer()

	slog.Info("Server starting", "port", 8081)
	if err := http.ListenAndServe(":8081", server.routes()); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}

// getEnv reads an environment variable or returns a fallback
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
