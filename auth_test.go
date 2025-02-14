package auth

import (
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

func TestFlow(t *testing.T) {

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

	u, err := auth.Register("user1", string(testPassword))
	if err != nil {
		t.Fatal(err)
	}

	accessToken, refreshToken, err := auth.Login(u.UserID, u.Password)
	if err != nil {
		t.Fatal(err)
	}

	if accessToken == "" || refreshToken == "" {
		t.Fatal("a token is blank")
	}

	_, err = auth.validateToken(accessToken)
	if err != nil {
		t.Errorf("access token: %s %v", accessToken, err)
	}

	_, err = auth.validateToken(refreshToken)
	if err != nil {
		t.Errorf("refresh token: %s %v", refreshToken, err)
	}

	accessToken, refreshToken, err = auth.Refresh(refreshToken)
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.validateToken(accessToken)
	if err != nil {
		t.Errorf("access token: %s %v", accessToken, err)
	}

	_, err = auth.validateToken(refreshToken)
	if err != nil {
		t.Errorf("refresh token: %s %v", refreshToken, err)
	}

	err = auth.Logout(u.UserID)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = auth.Refresh(refreshToken)
	if err == nil {
		t.Fatal("this should have errored as the refresh token no longer exists since the user logged out")
	}

}
