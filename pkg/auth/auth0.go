package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dimaskiddo/go-whatsapp-rest/pkg/crypt"
	"github.com/dimaskiddo/go-whatsapp-rest/pkg/router"
	"github.com/dimaskiddo/go-whatsapp-rest/pkg/server"
	jwt "github.com/form3tech-oss/jwt-go"
)

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func Auth0(next http.Handler) http.Handler {
	// Return Next HTTP Handler Function, If Authorization is Valid
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
			ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
				// Verify 'aud' claim
				aud := server.Config.GetString("AUTH0_AUDIENCE")
				checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
				if !checkAud {
					return token, errors.New("Invalid audience.")
				}
				// Verify 'iss' claim
				iss := server.Config.GetString("AUTH0_DOMAIN")
				checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
				if !checkIss {
					return token, errors.New("Invalid issuer.")
				}

				cert, err := GetPemCert(token)
				if err != nil {
					panic(err.Error())
				}

				key := server.Config.GetString("AUTH0_AUDIENCE") + "/jid"
				jid, ok := (token.Claims.(jwt.MapClaims))[key].(string)
				if !ok {
					return token, errors.New("No JID found in claims")
				}

				// Encrypt Claims Using RSA Encryption
				claimsEncrypted, err := crypt.EncryptWithRSA(jid)
				if err != nil {
					return token, errors.New(err.Error())
				}
				r.Header.Set("X-JWT-Claims", claimsEncrypted)

				result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))

				return result, nil
			},
			SigningMethod: jwt.SigningMethodRS256,
			// Debug:         true,
			ErrorHandler: HandleError,
		})

		jwtMiddleware.HandlerWithNext(w, r, next.ServeHTTP)
	})

}
func HandleError(w http.ResponseWriter, r *http.Request, err string) {
	router.ResponseInternalError(w, err)
}

func GetPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get(server.Config.GetString("AUTH0_DOMAIN") + ".well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	return cert, nil
}
