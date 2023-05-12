package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
)

// GetConsoleURL get AWS Management Console URL
// ref: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html
func GetConsoleURL() (string, error) {
	sess := createSession()
	if sess == nil {
		return "", errors.New("failed to get AWS session")
	}

	amazonDomain := getConsoleDomain(*sess.Config.Region)

	// Create get signin token URL
	creds, err := sess.Config.Credentials.Get()
	if err != nil {
		return "", errors.New("failed to get AWS session")
	}

	token, err := getSinginToken(creds, amazonDomain)
	if err != nil {
		return "", err
	}

	targetURL := fmt.Sprintf("https://console.%s/console/home", amazonDomain)
	params := url.Values{
		"Action":      []string{"login"},
		"Destination": []string{targetURL},
		"SigninToken": []string{token},
	}
	return fmt.Sprintf("https://signin.%s/federation?%s", amazonDomain, params.Encode()), nil
}

// Create Session
//
//	By default NewSession will only load credentials from the shared credentials file (~/.aws/credentials).
func createSession() *session.Session {
	return session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
}

// Get console domain from region
func getConsoleDomain(region string) string {
	var amazonDomain string

	if strings.HasPrefix(region, "us-gov-") {
		amazonDomain = "amazonaws-us-gov.com"
	} else if strings.HasPrefix(region, "cn-") {
		amazonDomain = "amazonaws.cn"
	} else {
		amazonDomain = "aws.amazon.com"
	}
	return amazonDomain
}

// Get signin token
func getSinginToken(creds credentials.Value, amazonDomain string) (string, error) {
	urlCreds := map[string]string{
		"sessionId":    creds.AccessKeyID,
		"sessionKey":   creds.SecretAccessKey,
		"sessionToken": creds.SessionToken,
	}

	bytes, err := json.Marshal(urlCreds)
	if err != nil {
		return "", err
	}
	params := url.Values{
		"Action":  []string{"getSigninToken"},
		"Session": []string{string(bytes)},
	}
	tokenRequest := fmt.Sprintf("https://signin.%s/federation?%s", amazonDomain, params.Encode())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Construct a request to the federation URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenRequest, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed: %s", resp.Status)
	}

	// Extract a signin token from the response body.
	token, err := getToken(resp.Body)
	if err != nil {
		return "", err
	}
	return token, nil
}

func getToken(reader io.Reader) (string, error) {
	type response struct {
		SigninToken string
	}

	var resp response
	if err := json.NewDecoder(reader).Decode(&resp); err != nil {
		return "", err
	}

	return resp.SigninToken, nil
}
