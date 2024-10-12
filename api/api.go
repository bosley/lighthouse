package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type LighthouseAPI struct {
	client          *http.Client
	baseURL         string
	authToken       string
	allowSelfSigned bool
}

type ApiResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type NewUser struct {
	Email    string `json:"email" validate:"required,email"`
	Username string `json:"username" validate:"required,min=3,max=30"`
	Password string `json:"password" validate:"required,min=8"`
}

type UserLogin struct {
	Email             string `json:"email"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	RequestedDuration string `json:"requested_duration"`
}

type APIOption func(*LighthouseAPI)

func WithSelfSignedCerts() APIOption {
	return func(api *LighthouseAPI) {
		api.allowSelfSigned = true
	}
}

func NewLighthouseAPI(baseURL string, options ...APIOption) *LighthouseAPI {
	api := &LighthouseAPI{
		baseURL: baseURL,
	}

	for _, option := range options {
		option(api)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: api.allowSelfSigned},
	}

	api.client = &http.Client{
		Transport: transport,
		Timeout:   time.Second * 30,
	}

	return api
}

func (api *LighthouseAPI) CreateUser(email, username, password string) (string, error) {
	newUser := NewUser{
		Email:    email,
		Username: username,
		Password: password,
	}

	resp, err := api.sendRequest("POST", "/api/v1/users/new", newUser)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var apiResp ApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error: %s", apiResp.Message)
	}

	return apiResp.Message, nil
}

func (api *LighthouseAPI) VerifyUser(magicLink string) error {
	req, err := http.NewRequest("GET", api.baseURL+"/api/v1/verify", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Lighthouse-Magic-Link", magicLink)

	resp, err := api.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	var apiResp ApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error: %s", apiResp.Message)
	}

	return nil
}

func (api *LighthouseAPI) LoginUser(email, username, password, requestedDuration string) (string, error) {
	loginData := UserLogin{
		Email:             email,
		Username:          username,
		Password:          password,
		RequestedDuration: requestedDuration,
	}

	resp, err := api.sendRequest("POST", "/api/v1/auth", loginData)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var apiResp ApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error: %s", apiResp.Message)
	}

	api.authToken = apiResp.Message
	return api.authToken, nil
}

func (api *LighthouseAPI) Logout() error {
	if api.authToken == "" {
		return fmt.Errorf("user is not currently logged in")
	}

	err := api.Blacklist(api.authToken)
	if err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}

	api.authToken = "" // Clear the auth token after successful logout
	return nil
}

func (api *LighthouseAPI) Blacklist(token string) error {
	resp, err := api.sendRequest("GET", "/api/v1/vip/blacklist/"+token, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var apiResp ApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(apiResp.Message)
	}

	return nil
}

func (api *LighthouseAPI) sendRequest(method, endpoint string, data interface{}) (*http.Response, error) {
	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request data: %w", err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, api.baseURL+endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if api.authToken != "" {
		req.Header.Set("Lighthouse-Token", api.authToken)
	}

	resp, err := api.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	return resp, nil
}

// GetClient returns the http.Client for testing purposes
func (api *LighthouseAPI) GetClient() *http.Client {
	return api.client
}
