package handlers

// The agents need to be authorized. This should be done with a JWT token handed out by the server
// when the agent is registered. The token should be stored in the agent's config file and sent

import (
	"encoding/json"
	"errors"

	"github.com/RunawayVPN/Runaway-Hub/tools/auth"
	sec "github.com/RunawayVPN/security"
	"github.com/RunawayVPN/types"
	"github.com/gin-gonic/gin"
)

const SECRET_KEY = "secret"

func RegisterAgent(c *gin.Context) {
	var request types.RegistrationRequest
	check_error(c, c.BindJSON(&request), 400)
	// Check secret key
	if request.SecretKey != SECRET_KEY {
		if check_error(c, errors.New("invalid secret key"), 401) {
			return
		}
	}
	// Unmarshal payload
	var agent types.Agent = request.Agent
	// Register to database
	if check_error(c, auth.RegisterAgent(agent), 500) {
		return
	}
	// Create Auth token
	auth_token := types.AuthToken{
		Endpoint: agent.PublicIP,
		Roles:    []string{"agent"},
	}
	// Convert to JSON string
	auth_token_json, err := json.Marshal(auth_token)
	if check_error(c, err, 500) {
		return
	}
	// Create JWT
	auth_token_jwt, err := sec.CreateToken(string(auth_token_json))
	if check_error(c, err, 500) {
		return
	}

	c.JSON(200, types.RegistrationResponse{
		Success:   true,
		PublicKey: sec.EncodeBS(sec.Public_key),
		AuthToken: auth_token_jwt,
	})
}

func check_error(c *gin.Context, err error, code int) bool {
	if err != nil {
		c.JSON(code, types.RegistrationResponse{
			Success: false,
			Error:   err.Error(),
		})
		return true
	}
	return false
}
