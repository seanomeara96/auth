package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestNewErr(t *testing.T) {
	err := newErr(internalErr, "error")
	if err == nil {
		t.Error(err)
	}
	if err.t != internalErr {
		t.Error("expected an internal error")
	}
}

func TestBasicFlow(t *testing.T) {

	dir, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for i := range dir {
		file := dir[i]
		if file.Name() == "auth.db" {
			if err := os.Remove(file.Name()); err != nil {
				t.Fatal(err)
			}
		}
	}

	ctx := context.Background()

	auth, err := Init(AuthConfig{
		JWTSecretKey: "super_secret_test_key",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()

	testPassword, err := bcrypt.GenerateFromPassword([]byte(`password`), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	u, err := auth.Register(ctx, "user1", string(testPassword))
	if err != nil {
		t.Fatal(err)
	}

	accessToken, refreshToken, err := auth.Login(ctx, u.UserID, u.Password)
	if err != nil {
		t.Fatal(err)
	}

	if accessToken == "" || refreshToken == "" {
		t.Fatal("a token is blank")
	}

	_, err = auth.ValidateToken(accessToken)
	if err != nil {
		t.Errorf("access token: %s %v", accessToken, err)
	}

	_, err = auth.ValidateToken(refreshToken)
	if err != nil {
		t.Errorf("refresh token: %s %v", refreshToken, err)
	}

	accessToken, refreshToken, err = auth.Refresh(ctx, refreshToken)
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.ValidateToken(accessToken)
	if err != nil {
		t.Errorf("access token: %s %v", accessToken, err)
	}

	_, err = auth.ValidateToken(refreshToken)
	if err != nil {
		t.Errorf("refresh token: %s %v", refreshToken, err)
	}

	err = auth.Logout(ctx, refreshToken)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = auth.Refresh(ctx, refreshToken)
	if err == nil {
		t.Fatal("this should have errored as the refresh token no longer exists since the user logged out")
	}

	// once valid token from a previous test
	expiredToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjowLCJleHAiOjE3Mzk4MDMwMDIsImp0aSI6ImNiZDE1MjgxLTI2YzItNGUzYi05ODY5LWZkNjRkZGI1MWZiMSJ9.LqDreR5kS-bVOgC_Tf2SSpArAEbnLv-mx2E_HKj0r6c"
	_, err = auth.ValidateToken(expiredToken)
	if err == nil {
		t.Fatal(err)
	}

}

func TestServerFlow(t *testing.T) {
	dir, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for i := range dir {
		file := dir[i]
		if file.Name() == "auth.db" {
			if err := os.Remove(file.Name()); err != nil {
				t.Fatal(err)
			}
		}
	}

	ctx := context.Background()

	auth, err := Init(AuthConfig{
		JWTSecretKey: "super_secret_test_key",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()

	testPassword, err := bcrypt.GenerateFromPassword([]byte(`password`), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	u, err := auth.Register(ctx, "user1", string(testPassword))
	if err != nil {
		t.Fatal(err)
	}

	loginHandler := func(w http.ResponseWriter, r *http.Request) {
		aToken, rToken, err := auth.Login(ctx, u.UserID, u.Password)
		if err != nil {
			http.Error(w, "could not login", 500)
			return
		}
		auth.SetTokens(w, aToken, rToken)
	}

	middleHandler := func(w http.ResponseWriter, r *http.Request) {
		aToken, rToken, err := auth.GetTokensFromRequest(r)
		if err != nil {
			http.Error(w, "could not get tokens from request", 500)
			return
		}

		_, err = auth.ValidateToken(aToken)
		if err != nil {
			aToken, rToken, err = auth.Refresh(ctx, rToken)
			if err != nil {
				http.Error(w, "could not validate or refresh token", 500)
				return
			}
			auth.SetTokens(w, aToken, rToken)
		}

		//do some stuff

	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", loginHandler)
	mux.HandleFunc("GET /middle", middleHandler)
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	// Check if refresh token cookie is set
	cookies := rr.Result().Cookies()
	var refreshTokenSet bool
	var accessTokenSet bool
	for _, cookie := range cookies {
		if cookie.Name == "refresh_token" {
			refreshTokenSet = true
		}
		if cookie.Name == "access_token" {
			accessTokenSet = true
		}
	}
	if !refreshTokenSet {
		t.Errorf("expected refresh token cookie to be set")
	}
	if !accessTokenSet {
		t.Errorf("expected access token cookie to be set")
	}
}
