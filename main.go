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
)

//Auth.go
//GET

func FetchrenderTenantLoginPage()

// Client.go

// POST
func CreateClientForTenant(ctx context.Context, tenantName string, clientRequest ClientRequest, r *http.Request) (*ClientResponse, error) {
	url := fmt.Sprintf("%s/api/tenants/%s/clients", os.Getenv("ADMIN_API_BASE_URL"), tenantName)

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

type responseData struct {
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
