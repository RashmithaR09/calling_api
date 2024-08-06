package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"text/template"
)

//Auth.go
//GET

func FetchRegisterOAuthRoutes(w http.ResponseWriter, r *http.Request) {

	url := fmt.Sprintf("%s/auth/tenant/login", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"))

	resp, err := http.Get(url)

	if err != nil {
		http.Error(w, "Failed to connect to third-party server", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Third-party server returned status: %d", resp.StatusCode), http.StatusInternalServerError)
		return
	}

	data := struct {
		RedirectUri string
	}{
		RedirectUri: r.URL.Query().Get("redirect-uri"),
	}

	tmpl, err := template.ParseFiles("tenant-login.html")
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

// POST
func FetchtenantLoginHandler(ctx context.Context, loginRequest LoginRequest, w http.ResponseWriter, r *http.Request) (*LoginRequest, error) {
	url := fmt.Sprintf("%s/auth/tenant/login", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"))

	reqBody, err := json.Marshal(loginRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	token := r.Header.Get("Authorization")
	if token == "" {
		return nil, fmt.Errorf("Authorization token is missing")
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create client: %s, response body: %s", resp.Status, string(body))
	}

	var response LoginRequest
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

type LoginRequest struct {
	Email       string `form:"email" binding:"required"`
	Password    string `form:"password" binding:"required"`
	RedirectURI string `form:"redirect_uri" binding:"required"`
	Scope       string `form:"scope" binding:"required"`
}

// GET

func FetchauthorizationHandler(tenantName string, ctx context.Context, w http.ResponseWriter, r *http.Request) (*Tenant, error) {
	url := fmt.Sprintf("%s/auth/:%s/authorize", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer your_token_here")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data: %s, response body: %s", resp.Status, string(body))
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		return nil, err
	}

	return responseData, nil

}

// Client.go

// POST
func CreateClientForTenant(ctx context.Context, tenantName string, clientRequest ClientRequest, r *http.Request) (*ClientResponse, error) {
	url := fmt.Sprintf("%s/api/tenants/%s/clients", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName)

	reqBody, err := json.Marshal(clientRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	// Retrieve the authorization token from the request header
	token := r.Header.Get("Authorization")
	if token == "" {
		return nil, fmt.Errorf("Authorization token is missing")
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create client: %s, response body: %s", resp.Status, string(body))
	}

	var clientResponse ClientResponse
	if err := json.Unmarshal(body, &clientResponse); err != nil {
		return nil, err
	}

	return &clientResponse, nil

}

type ClientRequest struct {
	RedirectURIs string
}

type ClientResponse struct {
	ID           uint
	ClientID     string
	ClientSecret string
}

// GET
func FetchgetAllClientsHandler(ctx context.Context, tenantName string, r *http.Request) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/tenants/%s/clients", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName)
	fmt.Println(url)
	fmt.Println(tenantName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer your_token_here")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data: %s, response body: %s", resp.Status, string(body))
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		return nil, err
	}

	return responseData, nil
}

// GET
func FetchgetClientHandler(ctx context.Context, tenantName string, clientID uint) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/tenants/:%s/clients/:%d", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName, clientID)
	fmt.Println(url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer your_token_here")
	req.Header.Set("Content-Type", "application/json")

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data: %s, response body: %s", resp.Status, string(body))
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		return nil, err
	}

	return responseData, nil

}

type response struct {
	ID           uint
	ClientID     string
	ClientSecret string
}

// DELETE
func FetchDeleteClientHandler(ctx context.Context, tenantName string, clientID uint) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/tenants/:%s/clients/:%d", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName, clientID)
	fmt.Println("DELETE Request URL:", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer your_token_here")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data: %s, response body: %s", resp.Status, string(body))
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		return nil, err
	}

	return responseData, nil
}

//user.go
//POST

func FetchcreateUserHandler(ctx context.Context, tenantName string, userRequest UserRequest, r *http.Request) (*UserResponse, error) {
	url := fmt.Sprintf("%s/tenants/:%s/users", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName)

	reqBody, err := json.Marshal(userRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	// Retrieve the authorization token from the request header
	token := r.Header.Get("Authorization")
	if token == "" {
		return nil, fmt.Errorf("authorization token is missing")
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create client: %s, response body: %s", resp.Status, string(body))
	}

	var userResponse UserResponse
	if err := json.Unmarshal(body, &userResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %v", err)
	}

	return &userResponse, nil

}

type UserRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type UserResponse struct {
	ID        uint   `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// GET
func FetchgetAllUsersHandler(ctx context.Context, tenantName string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/tenants/:%s/users", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName)
	fmt.Println(url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer your_token_here")
	req.Header.Set("Content-Type", "application/json")

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data: %s, response body: %s", resp.Status, string(body))
	}

	var UserResponse map[string]interface{}
	if err := json.Unmarshal(body, &UserResponse); err != nil {
		return nil, err
	}

	return UserResponse, nil

}

// GET
func FetchgetUserHandler(ctx context.Context, tenantName string, userID uint) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/tenants/:%s/users/:%d", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName, userID)
	fmt.Println(url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer your_token_here")
	req.Header.Set("Content-Type", "application/json")

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data: %s, response body: %s", resp.Status, string(body))
	}

	var UserResponse map[string]interface{}
	if err := json.Unmarshal(body, &UserResponse); err != nil {
		return nil, err
	}

	return UserResponse, nil

}

// PUT
func FetchupdateUserHandler(ctx context.Context, tenantName string, userId int, user UserRequest) (*UserResponse, error) {
	url := fmt.Sprintf("%s/tenants/:%s/users/:%d", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName, userId)

	userRequestBody, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(userRequestBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+os.Getenv("AUTH_TOKEN")) // Set your authorization token here
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update user, status code: %d", resp.StatusCode)
	}

	var userResponse UserResponse
	if err := json.NewDecoder(resp.Body).Decode(&userResponse); err != nil {
		return nil, err
	}
	return &userResponse, nil
}

// DELETE
func FetchdeleteUserHandler(ctx context.Context, tenantName string, clientID uint) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/tenants/:%s/users/:%d", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName, clientID)
	fmt.Println("DELETE Request URL:", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer your_token_here")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data: %s, response body: %s", resp.Status, string(body))
	}

	var UserResponse map[string]interface{}
	if err := json.Unmarshal(body, &UserResponse); err != nil {
		return nil, err
	}

	return UserResponse, nil
}

//POST

func FetchaddRolesToUserHandler(ctx context.Context, userId int, tenantName string, userRequest UserRequest, r *http.Request) (*UserResponse, error) {
	url := fmt.Sprintf("%s/tenants/:%s/users/:%d/roles", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName, userId)

	reqBody, err := json.Marshal(userRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	// Retrieve the authorization token from the request header
	token := r.Header.Get("Authorization")
	if token == "" {
		return nil, fmt.Errorf("authorization token is missing")
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to add roles to user: %s, response body: %s", resp.Status, string(body))
	}

	var userResponse UserResponse
	if err := json.Unmarshal(body, &userResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %v", err)
	}

	return &userResponse, nil
}

// GET
func FetchgetUserRolesHandler(ctx context.Context, tenantName string, userID uint) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/tenants/:%s/users/:%d/roles", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName, userID)
	fmt.Println(url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer your_token_here")
	req.Header.Set("Content-Type", "application/json")

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch data: %s, response body: %s", resp.Status, string(body))
	}

	var UserResponse map[string]interface{}
	if err := json.Unmarshal(body, &UserResponse); err != nil {
		return nil, err
	}

	return UserResponse, nil

}

// DELETE
func FetchremoveRolesFromUserHandler(ctx context.Context, tenantName string, userID uint) error {
	url := fmt.Sprintf("%s/tenants/:%s/users/:%d/roles", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantName, userID)
	fmt.Println("DELETE Request URL:", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer your_token_here")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch data: %s, response body: %s", resp.Status, string(body))
	}

	var UserResponse map[string]interface{}
	if err := json.Unmarshal(body, &UserResponse); err != nil {
		return err
	}

	return err
}

// Tenant.go

func FetchcreateTenantHandler(w http.ResponseWriter, r *http.Request) (*TenantUpdateResponse, error) {
	var req TenantCreateRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid tenant data", http.StatusBadRequest)
		return nil, err

	}
	url := fmt.Sprintf("%s/master/tenants", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"))
	// fmt.Println("Post URL:", url)

	reqBody, err := json.Marshal(req)
	if err != nil {
		http.Error(w, "Failed to marshal request body", http.StatusInternalServerError)
		return nil, err
	}

	ctx := context.Background()
	req3rdParty, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return nil, err

	}

	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization token is missing", http.StatusUnauthorized)
		return nil, err

	}
	req3rdParty.Header.Set("Authorization", token)
	req3rdParty.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req3rdParty)
	if err != nil {
		http.Error(w, "Failed to send request", http.StatusInternalServerError)
		return nil, err

	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return nil, err

	}

	if resp.StatusCode != http.StatusCreated {
		http.Error(w, fmt.Sprintf("Failed to create tenant: %s, response body: %s", resp.Status, string(body)), resp.StatusCode)
		return nil, err

	}
	var response TenantUpdateResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return &response, nil

}

type TenantCreateRequest struct {
	TenantName  string `json:"tenant_name"`
	DisplayName string `json:"display_name"`
}

type TenantUpdateResponse struct {
	ID          uint   `json:"id"`
	TenantName  string `json:"tenant_name"`
	DisplayName string `json:"display_name"`
}

// GET
func FetchgetAllTenantsHandler(w http.ResponseWriter, r *http.Request) (*TenantUpdateRequest, error) {
	url := fmt.Sprintf("%s/master/tenants", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"))

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return nil, err
	}

	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization token is missing", http.StatusUnauthorized)
		return nil, err
	}
	req.Header.Set("Authorization", token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to send request", http.StatusInternalServerError)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Failed to retrieve tenants: %s, response body: %s", resp.Status, string(body)), resp.StatusCode)
		return nil, err
	}

	var response TenantUpdateRequest
	if err := json.Unmarshal(body, &response); err != nil {
		http.Error(w, "Failed to unmarshal response body", http.StatusInternalServerError)
		return nil, err
	}
	return &response, nil
}

type TenantUpdateRequest struct {
	DisplayName string `json:"display_name"`
}

//GET

func FetchgetTenantHandler(tenantID int, w http.ResponseWriter, r *http.Request) (*TenantUpdateRequest, error) {
	url := fmt.Sprintf("%s/master/tenants/:%d", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantID)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return nil, err
	}

	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization token is missing", http.StatusUnauthorized)
		return nil, err
	}

	req.Header.Set("Authorization", token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to send request", http.StatusInternalServerError)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Failed to retrieve tenants: %s, response body: %s", resp.Status, string(body)), resp.StatusCode)
		return nil, err
	}

	var response TenantUpdateRequest
	if err := json.Unmarshal(body, &response); err != nil {
		http.Error(w, "Failed to unmarshal response body", http.StatusInternalServerError)
		return nil, err
	}
	return &response, nil
}

func FetchupdateTenantHandler(tenantID int, w http.ResponseWriter, r *http.Request) (*TenantUpdateResponse, error) {
	var req TenantUpdateRequest

	id := r.URL.Query().Get("tenantID")
	if id == "" {
		http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
		return nil, fmt.Errorf("invalid tenant ID")
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid tenant data", http.StatusBadRequest)
		return nil, err
	}

	url := fmt.Sprintf("%s/master/tenants/:%d", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantID)

	reqBody, err := json.Marshal(req)
	if err != nil {
		http.Error(w, "Failed to marshal request body", http.StatusInternalServerError)
		return nil, err
	}
	ctx := context.Background()
	req3rdParty, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(reqBody))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return nil, err
	}

	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization token is missing", http.StatusUnauthorized)
		return nil, fmt.Errorf("authorization token is missing")
	}

	req3rdParty.Header.Set("Authorization", token)
	req3rdParty.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req3rdParty)
	if err != nil {
		http.Error(w, "Failed to send request", http.StatusInternalServerError)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Failed to update tenant: %s, response body: %s", resp.Status, string(body)), resp.StatusCode)
		return nil, fmt.Errorf("failed to update tenant: %s", resp.Status)
	}

	var response TenantUpdateResponse
	if err := json.Unmarshal(body, &response); err != nil {
		http.Error(w, "Failed to unmarshal response body", http.StatusInternalServerError)
		return nil, err
	}

	return &response, nil
}

//DELETE

func FetchdeleteTenantHandler(tenantID int, w http.ResponseWriter, r *http.Request) error {

	url := fmt.Sprintf("%s/master/tenants/:%d", os.Getenv("AIOTRIX-GAURD-IDP-API-URL"), tenantID)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, url, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return err
	}

	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization token is missing", http.StatusUnauthorized)
		return err
	}

	req.Header.Set("Authorization", token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to send request", http.StatusInternalServerError)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Failed to read response body", http.StatusInternalServerError)
			return err
		}
		http.Error(w, fmt.Sprintf("Failed to delete tenant: %s, response body: %s", resp.Status, string(body)), resp.StatusCode)
		return nil
	}

	return nil
}
