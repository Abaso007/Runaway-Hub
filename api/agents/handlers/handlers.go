package handlers

// The agents need to be authorized. This should be done with a JWT token handed out by the server
// when the agent is registered. The token should be stored in the agent's config file and sent

import (
	"encoding/json"
	"errors"

	"github.com/RunawayVPN/Runaway-Hub/tools/auth"
	sec "github.com/RunawayVPN/Runaway-Hub/tools/security"
	"github.com/RunawayVPN/types"
	"github.com/gin-gonic/gin"
)

const SECRET_KEY = "secret"

type UnverifiedRequest struct {
	PublicKey string `json:"public_key"`
	SecretKey string `json:"secret_key"`
	JwtToken  string `json:"jwt"`
}
type RegisterAgentResponse struct {
	Success   bool   `json:"success"`
	Error     string `json:"error"`
	PublicKey string `json:"public_key"`
	JwtToken  string `json:"jwt"`
}

func RegisterAgent(c *gin.Context) {
	var raw_request UnverifiedRequest
	check_error(c, c.BindJSON(&raw_request), 400)
	// Check secret key
	if raw_request.SecretKey != SECRET_KEY {
		if check_error(c, errors.New("invalid secret key"), 500) {
			return
		}
	}
	// Verify JWT
	request_payload, err := sec.VerifyToken(raw_request.JwtToken, raw_request.PublicKey)
	if check_error(c, err, 401) {
		return
	}
	// Unmarshal payload
	var agent types.Agent
	if check_error(c, json.Unmarshal([]byte(request_payload), &agent), 500) {
		return
	}
	if check_error(c, auth.RegisterAgent(agent), 500) {
		return
	}
	// Construct JWT payload with agent
	response_jwt_payload, err := json.Marshal(agent)
	if check_error(c, err, 500) {
		return
	}
	// Create JWT response_token
	response_token, err := sec.CreateToken(string(response_jwt_payload))
	if check_error(c, err, 500) {
		return
	}
	c.JSON(200, RegisterAgentResponse{
		Success:   true,
		PublicKey: sec.EncodeBS(sec.Public_key),
		JwtToken:  response_token,
	})
}

func check_error(c *gin.Context, err error, code int) bool {
	if err != nil {
		c.JSON(code, RegisterAgentResponse{
			Success: false,
			Error:   err.Error(),
		})
		return true
	}
	return false
}
