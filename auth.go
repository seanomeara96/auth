package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type auth struct {
	db                 *sql.DB
	jwtSecretKey       []byte
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
}

type AuthConfig struct {
	DB                 *sql.DB
	JWTSecretKey       string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	DatabaseSourceName string
}

type user struct {
	ID       int    `json:"id"`
	UserID   string `json:"uuid"`
	Password string `json:"password"`
}

type Claims struct {
	UserID int `json:"user_id"`
	jwt.StandardClaims
}

func (a *auth) Close() {
	a.db.Close()
}

func Init(config AuthConfig) (*auth, error) {

	a := auth{}

	if config.DatabaseSourceName == "" {
		config.DatabaseSourceName = "./auth.db"
	}

	/*var (
		jwtSecretKey       = []byte("supersecretkey")
		accessTokenExpiry  = time.Minute * 15
		refreshTokenExpiry = time.Hour * 24 * 7
	)*/

	if config.JWTSecretKey == "" {
		return nil, errors.New("must supply a jwt secret key")
	}
	a.jwtSecretKey = []byte(config.JWTSecretKey)

	if config.AccessTokenExpiry < (time.Minute * 15) {
		config.AccessTokenExpiry = time.Minute * 15
	}
	a.accessTokenExpiry = config.AccessTokenExpiry

	if config.RefreshTokenExpiry < (time.Hour * 24 * 7) {
		config.RefreshTokenExpiry = time.Hour * 24 * 7
	}
	a.refreshTokenExpiry = config.RefreshTokenExpiry

	if config.DB == nil {
		// Initialize SQLite database
		var err error
		a.db, err = sql.Open("sqlite3", config.DatabaseSourceName)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %v", err)
		}
	} else {
		a.db = config.DB
	}

	_, err := a.db.Exec(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT
	user_id TEXT NOT NULL,
	password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	token TEXT NOT NULL,
	expires_at DATETIME NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(id)
);`)
	if err != nil {
		return &a, err
	}

	return &a, nil
}

func (a *auth) Register(userID, password string) error {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Save user to database
	_, err = a.db.Exec("INSERT INTO users (user_id, password) VALUES (?, ?)", userID, string(hashedPassword))
	if err != nil {
		return fmt.Errorf("DB error orUser already exists %w", err)
	}

	return nil
}

func (a *auth) Login(userID, password string, w http.ResponseWriter) (accessToken string, refreshToken string, err error) {
	// Fetch user from database
	var storedUser user
	err = a.db.QueryRow("SELECT id, userID, password FROM users WHERE userID = ?", userID).Scan(&storedUser.ID, &storedUser.UserID, &storedUser.Password)
	if err != nil {
		return "", "", fmt.Errorf("error fetching stored user from db %w", err)
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(password)); err != nil {
		return "", "", fmt.Errorf("invalid credentials %v", err)
	}

	// Generate JWT tokens
	accessToken, err = a.generateToken(storedUser.ID, a.accessTokenExpiry)
	if err != nil {
		return "", "", fmt.Errorf("failed to create access token %v", err)
	}

	refreshToken, err = a.generateToken(storedUser.ID, a.refreshTokenExpiry)
	if err != nil {
		return "", "", fmt.Errorf("failed to create refresh token %v", err)
	}

	// Save refresh token to database
	_, err = a.db.Exec("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
		storedUser.ID, refreshToken, time.Now().Add(a.refreshTokenExpiry))
	if err != nil {
		return "", "", fmt.Errorf("failed to save refresh token %w", err)
	}

	return accessToken, refreshToken, nil
}

func (a *auth) SetTokens(w http.ResponseWriter, accessToken, refreshToken string) {

	// Set secure cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Expires:  time.Now().Add(a.accessTokenExpiry),
		HttpOnly: true,
		Secure:   true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Expires:  time.Now().Add(a.refreshTokenExpiry),
		HttpOnly: true,
		Secure:   true,
	})

}

func GetRefreshTokenFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		return "", fmt.Errorf("could not get refresh token from cookie: %v", err)
	}

	return cookie.Value, nil
}

/*
takes cookie.Value

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

refreshToken, err := GetRefreshtokenFromCookie(r)

	if err != nil {
		// ...
	}

accessToken, err := Refresh(refreshToken)

	if err != nil {
		// ...
	}

SetAccessToken(w, accessToken)
*/
func (a *auth) Refresh(refreshToken string) (accessToken string, err error) {
	// Validate refresh token
	claims, err := a.validateToken(refreshToken)
	if err != nil {
		return "", err
	}

	// Check if refresh token exists in database
	var exists bool
	err = a.db.QueryRow(
		"SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE user_id = ? AND token = ?)",
		claims.UserID, refreshToken,
	).Scan(&exists)
	if err != nil || !exists {
		return "", fmt.Errorf("Refresh token not valid %w", err)
	}

	// Generate new access token
	accessToken, err = a.generateToken(claims.UserID, a.accessTokenExpiry)
	if err != nil {
		return "", fmt.Errorf("failed to generate access token %w", err)
	}

	return accessToken, nil

}

func (a *auth) SetAccessToken(w http.ResponseWriter, accessToken string) {
	// Set new access token in secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Expires:  time.Now().Add(a.accessTokenExpiry),
		HttpOnly: true,
		Secure:   true,
	})
}

func (a *auth) generateToken(userID int, expiry time.Duration) (string, error) {
	claims := &Claims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expiry).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecretKey)
}

func (a *auth) validateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return a.jwtSecretKey, nil
	})

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}
