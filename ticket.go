package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

var ErrInvalidSigningMethod = fmt.Errorf("invalid signing method")
var ErrInvalidToken = fmt.Errorf("invalid token")
var ErrInvalidClaims = fmt.Errorf("invalid claims")

type Ticket interface {
	GetUserId() string
	IsAuthenticated() bool
	DoIfAuthenticated(authenticated func() error, unauthenticated func() error) error
	GetContext() context.Context
	AuthenticateTicket(userId string, user interface{}) error
	SaveToCookies(c *fiber.Ctx, signingKeyFunction func() (signingKey string, keyId string)) error
	ToJwtString(signingKeyFunction func() (signingKey string, keyId string)) (string, error)
	FromJwtString(tokenString string, signingKeyFunction func(keyId string) (signingKey string)) error
	RemoveFromCookies(c *fiber.Ctx) error
}

type TicketBase struct {
	ID              string `json:"id"`
	Authenticated   bool   `json:"authenticated"`
	AuthenticatedAt int64  `json:"authenticated_at"`
	ExpiresAt       int64  `json:"expires_at"`
	UserId          string `json:"user_id"`
}

func (t *TicketBase) AuthenticateTicket(userId string, user interface{}) error {
	t.ID = uuid.New().String()
	t.Authenticated = true
	t.AuthenticatedAt = time.Now().Unix()
	t.ExpiresAt = time.Now().Add(time.Duration(1) * time.Minute).Unix()
	t.UserId = userId
	return nil
}

func (t TicketBase) GetContext() context.Context {
	return context.TODO() // TODO: implement
}

func (t TicketBase) GetUserId() string {
	return t.UserId
}

func (t TicketBase) IsAuthenticated() bool {

	// Check if authenticated by authenticated flag
	if !t.Authenticated {
		return false
	}

	// Check if authenticated by authenticated at time
	if t.AuthenticatedAt > time.Now().Unix() {
		return false
	}

	// Check if authenticated by expires at time
	if t.ExpiresAt < time.Now().Unix() {
		return false
	}

	return t.Authenticated
}

func (t TicketBase) DoIfAuthenticated(authenticated func() error, unauthenticated func() error) error {
	if t.IsAuthenticated() {
		return authenticated()
	} else {
		return unauthenticated()
	}
}

func (t *TicketBase) FromJsonString(jsonString string) error {
	err := json.Unmarshal([]byte(jsonString), t)
	if err != nil {
		return err
	}
	return nil
}

func (t *TicketBase) ToJsonString() (string, error) {
	jsonString, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return string(jsonString), nil
}

func (t *TicketBase) SaveToCookies(c *fiber.Ctx, signingKeyFunction func() (signingKey string, keyId string)) error {
	jwtString, err := t.ToJwtString(signingKeyFunction)
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{
		Name:     "ticket",
		Value:    jwtString,
		HTTPOnly: true,
	})
	return nil
}

func (t *TicketBase) RemoveFromCookies(c *fiber.Ctx) error {
	c.Cookie(&fiber.Cookie{
		Name:     "ticket",
		Value:    "",
		HTTPOnly: true,
		Expires:  time.Now().Add(-1 * time.Hour),
	})
	return nil
}

func (t *TicketBase) ToJwtString(signingKeyFunction func() (signingKey string, keyId string)) (string, error) {

	// get json string
	jsonString, err := t.ToJsonString()
	if err != nil {
		return "", err
	}

	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"as": "token",
		"au": t.Authenticated,
		"d":  jsonString,
		"nbf": time.Now().Add(
			time.Duration(0) * time.Second,
		).Unix(),
	})

	// Get the signing key and key id
	signingKey, keyId := signingKeyFunction()

	// Set the key id
	token.Header["kid"] = keyId

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(signingKey))

	return tokenString, err
}

func (t *TicketBase) FromJwtString(tokenString string, signingKeyFunction func(keyId string) (signingKey string)) error {

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Get the key id
		keyId := token.Header["kid"].(string)
		// Get the signing key
		signingKey := signingKeyFunction(keyId)
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}
		// Return the signing key
		return []byte(signingKey), nil
	})
	if err != nil {
		return err
	}

	// Validate the token
	if !token.Valid {
		return ErrInvalidToken
	}

	// Get the claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ErrInvalidClaims
	}

	// Get the ticket json string
	ticketJsonString, ok := claims["d"].(string)
	if !ok {
		return ErrInvalidClaims
	}

	// Convert the ticket from json string
	err = t.FromJsonString(ticketJsonString)
	if err != nil {
		return err
	}

	return nil
}

func GetTicket(c interface{}) (ticket Ticket) {

	// Check if the context is nil
	if c == nil {
		return nil
	}

	// Get the ticket from the context if of type Fiber context
	if v, ok := c.(*fiber.Ctx); ok {
		found := v.Locals("ticket")
		if found != nil {
			return found.(Ticket)
		}
	}

	// return the default ticket
	return nil

}
