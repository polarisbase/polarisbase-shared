package fiber_middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/polarisbase/polaris-sdk/v3/shared"
)

func Tickets(
	signingKeyFunction func(keyId string) (signingKey string),
) func(c *fiber.Ctx) error {
	middleware := func(c *fiber.Ctx) error {

		// Set a custom header on all responses:
		c.Set("X-Tickets-Info", "Tickets-V1")

		// Try to get ticket from cookies

		if ticketCookieValue := c.Cookies("ticket"); ticketCookieValue != "" {

			// Create ticket
			ticket := &shared.TicketBase{}
			// Convert ticket from jwt
			if err := ticket.FromJwtString(ticketCookieValue, signingKeyFunction); err != nil {
				// Set ticket in context as empty (anonymous)
				c.Locals("ticket", &shared.TicketBase{})
				// Go to next middleware:
				return c.Next()
			}
			// Set ticket in context as authenticated (not empty)
			c.Locals("ticket", ticket)
			// Go to next middleware:
			return c.Next()

		} else if ticketAuthorizationValue := c.Get("Authorization"); ticketAuthorizationValue != "" {

			// Strip "Bearer " from the value
			ticketAuthorizationValue = ticketAuthorizationValue[7:]
			// Create ticket
			ticket := &shared.TicketBase{}
			// Convert ticket from jwt
			if err := ticket.FromJwtString(ticketAuthorizationValue, signingKeyFunction); err != nil {
				// Set ticket in context as empty (anonymous)
				c.Locals("ticket", &shared.TicketBase{})
				// Go to next middleware:
				return c.Next()
			}
			// Set ticket in context as authenticated (not empty)
			c.Locals("ticket", ticket)
			// Go to next middleware:
			return c.Next()

		}

		// Set ticket in context as empty (anonymous)
		c.Locals("ticket", &shared.TicketBase{})

		// Go to next middleware:
		return c.Next()

	}
	return middleware
}
