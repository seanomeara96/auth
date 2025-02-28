package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type Authenticator interface {
	Close() error
	GetAccessTokenFromRequest(r *http.Request) (string, error)
	GetRefreshTokenFromRequest(r *http.Request) (string, error)
	GetTokensFromRequest(r *http.Request) (accessToken string, refreshToken string, err error)
	IsTokenBlacklisted(ctx context.Context, tokenString string) (bool, error)
	Login(ctx context.Context, userID string, password string) (accessToken string, refreshToken string, err error)
	Logout(ctx context.Context, refreshToken string) error
	Refresh(ctx context.Context, refreshToken string) (newAccessToken string, newRefreshToken string, err error)
	Register(ctx context.Context, userID string, password string) (*user, error)
	SetAccessToken(w http.ResponseWriter, accessToken string)
	SetRefreshToken(w http.ResponseWriter, refreshToken string)
	SetTokens(w http.ResponseWriter, accessToken string, refreshToken string)
	UpdatePassword(ctx context.Context, userID string, password string) error
	ValidateToken(tokenString string) (*Claims, error)
}

type authErrorType string

const internalErr authErrorType = authErrorType("internal")
const clientErr authErrorType = authErrorType("client")

type authError struct {
	t authErrorType
	e error
}

func (ae authError) Error() string {
	return fmt.Sprintf(`%s error occured in auth lib: %v`, ae.t, ae.e)
}

var errAuthDefault = errors.New("an error occurred in auth lib")

func newErr(t authErrorType, msg interface{}) *authError {
	err, ok := msg.(error)
	if !ok {
		str, ok := msg.(string)
		if !ok {
			err = errAuthDefault
		} else {
			err = errors.New(str)
		}
	}
	return &authError{
		t: t,
		e: err,
	}
}

type auth struct {
	db                   *sql.DB
	jwtSecretKey         []byte
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
	cookieSecure         bool
	httpOnly             bool
	sameSite             http.SameSite
	cleanupTicker        *time.Ticker
	tickerStopChannel    chan struct{}
	wg                   sync.WaitGroup
}

type AuthConfig struct {
	DB                   *sql.DB
	JWTSecretKey         string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	DatabaseSourceName   string
	CookieSecure         bool
	HttpOnly             bool
	SameSite             http.SameSite
}

type user struct {
	id       int
	UserID   string `json:"uuid"`
	Password string `json:"password"`
}

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

/*
If Close() is called while a cleanup is running, db.Close() could execute before the cleanup finishes,
potentially causing a "database is closed" error or panic.
SQLite’s locking might prevent this, but it’s not guaranteed with other databases.
*/
func (a *auth) Close() error {
	if a.tickerStopChannel != nil {
		close(a.tickerStopChannel)
		a.wg.Wait()
	}
	if a.db != nil {
		return a.db.Close()
	}
	return nil
}

func Init(config AuthConfig) (Authenticator, error) {

	a := &auth{}

	if config.DatabaseSourceName == "" {
		config.DatabaseSourceName = "./auth.db"
	}

	/*var (
		jwtSecretKey       = []byte("supersecretkey")
		accessTokenExpiry  = time.Minute * 15
		refreshTokenExpiry = time.Hour * 24 * 7
	)*/

	if config.JWTSecretKey == "" {
		return nil, newErr(internalErr, "must supply a jwt secret key")
	}
	a.jwtSecretKey = []byte(config.JWTSecretKey)

	if config.AccessTokenDuration < (time.Minute * 15) {
		config.AccessTokenDuration = time.Minute * 15
	}
	a.accessTokenDuration = config.AccessTokenDuration

	if config.RefreshTokenDuration < (time.Hour * 24 * 7) {
		config.RefreshTokenDuration = time.Hour * 24 * 7
	}
	a.refreshTokenDuration = config.RefreshTokenDuration

	if config.DB == nil {
		// Initialize SQLite database
		var err error
		a.db, err = sql.Open("sqlite3", config.DatabaseSourceName)
		if err != nil {
			return nil, newErr(internalErr, fmt.Errorf("failed to connect to database: %w", err))
		}
	} else {
		a.db = config.DB
	}

	_, err := a.db.Exec(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	token TEXT NOT NULL UNIQUE,
	expires_at DATETIME NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS blacklisted_tokens(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	token TEXT NOT NULL UNIQUE,
	blacklisted_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS login_attempts(
	user_id INTEGER NOT NULL,
	attempt_count INTEGER DEFAULT 0,
	last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
`)
	if err != nil {
		return a, newErr(internalErr, fmt.Errorf("an error occured when trying to initalise the tables: %w", err))
	}

	a.cleanupTicker = time.NewTicker(time.Hour)
	a.tickerStopChannel = make(chan struct{})
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.cleanupExpiredTokens(context.Background())
		for {
			select {
			case <-a.cleanupTicker.C:
				func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
					defer cancel()
					if err := a.cleanupExpiredTokens(ctx); err != nil {
						log.Printf("Cleanup failed: %v", err) // Replace with your logger
					}
				}()
			case <-a.tickerStopChannel:
				a.cleanupTicker.Stop()
				return
			}
		}
	}()

	return a, nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password too short")
	}
	return nil
}

func (a *auth) blacklistToken(ctx context.Context, tokenString string) error {
	_, err := a.db.ExecContext(ctx, `INSERT INTO blacklisted_tokens(token)VALUES(?)`, tokenString)
	return err
}

func (a *auth) IsTokenBlacklisted(ctx context.Context, tokenString string) (bool, error) {
	var exists bool = false
	err := a.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM blacklisted_tokens WHERE token = ?)`, tokenString).Scan(&exists)
	return exists, err
}

func (a *auth) Register(ctx context.Context, userID, password string) (*user, error) {

	if err := validatePassword(password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, newErr(internalErr, fmt.Errorf("failed to hash password during register: %w", err))
	}

	// Save user to database
	res, err := a.db.ExecContext(ctx, "INSERT INTO users (user_id, password) VALUES (?, ?)", userID, string(hashedPassword))
	if err != nil {
		return nil, newErr(internalErr, fmt.Errorf("DB error orUser already exists %w", err))
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	var user user
	user.id = int(id)
	user.UserID = userID
	user.Password = password

	return &user, nil
}

func (a *auth) UpdatePassword(ctx context.Context, userID, password string) error {

	if err := validatePassword(password); err != nil {
		return err
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return newErr(internalErr, fmt.Errorf("failed to hash password during register: %w", err))
	}

	// Save user to database
	res, err := a.db.ExecContext(ctx, "UPDATE users SET password = ? WHERE user_id = ?", string(hashedPassword), userID)
	if err != nil {
		return newErr(internalErr, fmt.Errorf("DB failed to update password %w", err))
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return newErr(internalErr, err)
	}

	if rowsAffected == 0 {
		return newErr(clientErr, "no user password was updated. likely no matching user id")
	}

	return nil
}

func (a *auth) getUserDetails(ctx context.Context, userID string) (*user, error) {
	var storedUser user
	err := a.db.QueryRowContext(ctx, "SELECT id, user_id, password FROM users WHERE user_id = ?", userID).Scan(&storedUser.id, &storedUser.UserID, &storedUser.Password)
	if err != nil {
		return nil, err
	}
	return &storedUser, nil
}

func (a *auth) Login(ctx context.Context, userID, password string) (accessToken string, refreshToken string, err error) {
	// Fetch user from database
	storedUser, err := a.getUserDetails(ctx, userID)
	if err != nil {
		return "", "", newErr(internalErr, fmt.Errorf("error fetching stored user from db %w", err))
	}

	var attemptCount int
	var lastAttempt time.Time
	err = a.db.QueryRowContext(ctx, `SELECT attempt_count, last_attempt FROM login_attempts WHERE user_id = ?`, storedUser.id).Scan(&attemptCount, &lastAttempt)
	if err != nil && err != sql.ErrNoRows {
		return "", "", newErr(internalErr, fmt.Errorf("failed to get attempt count from db %w", err))
	}

	if attemptCount > 5 && time.Since(lastAttempt) > 15*time.Minute {
		return "", "", newErr(clientErr, "too many login attempts; try again later")
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(password)); err != nil {
		_, err = a.db.ExecContext(ctx,
			"INSERT OR REPLACE INTO login_attempts (user_id, attempt_count, last_attempt) VALUES (?, ?, ?)",
			storedUser.id, attemptCount+1, time.Now(),
		)
		return "", "", newErr(clientErr, fmt.Errorf("invalid credentials %w", err))
	}

	// Generate JWT tokens
	accessToken, err = a.generateToken(storedUser.id, a.accessTokenDuration)
	if err != nil {
		return "", "", newErr(internalErr, fmt.Errorf("failed to create access token %w", err))
	}

	refreshToken, err = a.generateToken(storedUser.id, a.refreshTokenDuration)
	if err != nil {
		return "", "", newErr(internalErr, fmt.Errorf("failed to create refresh token %w", err))
	}

	if err := a.saveRefreshToken(ctx, storedUser.id, refreshToken); err != nil {
		return "", "", newErr(internalErr, fmt.Errorf("failed to save refresh token during login"))
	}

	return accessToken, refreshToken, nil
}

func (a *auth) Logout(ctx context.Context, refreshToken string) error {

	if _, err := a.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token = ?`, refreshToken); err != nil {
		return newErr(internalErr, fmt.Errorf(`failed to delete from refresh tokens at logout: %w`, err))
	}

	if err := a.blacklistToken(ctx, refreshToken); err != nil {
		return err
	}

	return nil
}

func (a *auth) saveRefreshToken(ctx context.Context, userID int, refreshToken string) error {
	// Save refresh token to database
	_, err := a.db.ExecContext(ctx, "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
		userID, refreshToken, time.Now().Add(a.refreshTokenDuration))
	if err != nil {
		return newErr(internalErr, fmt.Errorf("failed to save refresh token %w", err))
	}
	return nil
}

func (a *auth) SetAccessToken(w http.ResponseWriter, accessToken string) {
	// Set new access token in secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Expires:  time.Now().Add(a.accessTokenDuration),
		HttpOnly: a.httpOnly,
		Secure:   a.cookieSecure,
		SameSite: a.sameSite,
	})
}

func (a *auth) SetRefreshToken(w http.ResponseWriter, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Expires:  time.Now().Add(a.refreshTokenDuration),
		HttpOnly: a.httpOnly,
		Secure:   a.cookieSecure,
		SameSite: a.sameSite,
	})
}

func (a *auth) SetTokens(w http.ResponseWriter, accessToken, refreshToken string) {
	// Set secure cookies
	a.SetAccessToken(w, accessToken)
	a.SetRefreshToken(w, refreshToken)
}

func (a *auth) GetTokensFromRequest(r *http.Request) (accessToken string, refreshToken string, err error) {
	accessToken, err = a.GetAccessTokenFromRequest(r)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = a.GetRefreshTokenFromRequest(r)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, err
}

func (a *auth) GetRefreshTokenFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		return "", newErr(internalErr, fmt.Errorf("could not get refresh token from cookie: %w", err))
	}

	return cookie.Value, nil
}

func (a *auth) GetAccessTokenFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		return "", newErr(internalErr, fmt.Errorf("could not get access token from cookie: %w", err))
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
func (a *auth) Refresh(ctx context.Context, refreshToken string) (newAccessToken string, newRefreshToken string, err error) {

	blacklisted, err := a.IsTokenBlacklisted(ctx, refreshToken)
	if err != nil {
		return "", "", err
	}

	if blacklisted {
		return "", "", newErr(clientErr, "provided token is blacklisted")
	}

	// Validate refresh token
	claims, err := a.ValidateToken(refreshToken)
	if err != nil {
		return "", "", err
	}

	// Check if refresh token exists in database
	var exists bool
	err = a.db.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE user_id = ? AND token = ?)",
		claims.UserID, refreshToken,
	).Scan(&exists)
	if err != nil {
		return "", "", newErr(internalErr, fmt.Errorf(`could not determine existence of refresh token. %w`, err))
	}
	if !exists {
		return "", "", newErr(clientErr, "Refresh token not valid")
	}

	// Generate new access token
	newAccessToken, err = a.generateToken(claims.UserID, a.accessTokenDuration)
	if err != nil {
		return "", "", newErr(internalErr, fmt.Errorf("failed to generate access token in refresh function %w", err))
	}

	newRefreshToken, err = a.generateToken(claims.UserID, a.refreshTokenDuration)
	if err != nil {
		return "", "", newErr(internalErr, fmt.Errorf("failed to generate refresh token in refresh function %w", err))
	}

	if err := a.saveRefreshToken(ctx, claims.UserID, newRefreshToken); err != nil {
		return "", "", newErr(internalErr, fmt.Errorf("failed to save new refresh token during refresh: %w", err))
	}

	_, err = a.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE token = ?", refreshToken)
	if err != nil {
		return "", "", newErr(internalErr, fmt.Errorf("failed to delete old refresh token %w", err))
	}

	if err := a.blacklistToken(ctx, refreshToken); err != nil {
		return "", "", newErr(internalErr, "failed to blacklist refresh token during refresh")
	}

	return newAccessToken, newRefreshToken, nil

}

func (a *auth) generateToken(userID int, expiry time.Duration) (string, error) {
	// Generate a random UUID
	randomID := uuid.New().String()

	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			ID:        randomID, // Add the random UUID as the JWT ID
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecretKey)
}

func (a *auth) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return a.jwtSecretKey, nil
	})
	if err != nil {
		return nil, newErr(internalErr, fmt.Errorf(`failed to parse with claims while validating token: %w`, err))
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, newErr(clientErr, `invalid access token cannot be validated`)
}

func (a *auth) cleanupExpiredTokens(ctx context.Context) error {
	tx, err := a.db.Begin()
	if err != nil {
		return newErr(internalErr, fmt.Errorf("could not create tx: %w", err))
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < ?`, time.Now())
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return newErr(internalErr, fmt.Errorf("failed to delete refresh tokens: %w; rollback failed: %v", err, rollbackErr))
		}
		return newErr(internalErr, fmt.Errorf("failed to delete refresh tokens: %w", err))
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM blacklisted_tokens WHERE blacklisted_at < ?`, time.Now().Add(-24*7*time.Hour))
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return newErr(internalErr, fmt.Errorf("failed to delete blacklisted tokens: %w; rollback failed: %v", err, rollbackErr))
		}
		return newErr(internalErr, fmt.Errorf("failed to delete blacklisted tokens: %w", err))
	}

	if err := tx.Commit(); err != nil {
		return newErr(internalErr, fmt.Errorf("failed to commit cleanup transaction: %w", err))
	}
	return nil
}
