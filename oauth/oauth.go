package oauth

import (
	http_client "bookstore_oauth-go/clients/http"
	errors_utils "bookstore_oauth-go/utils/errors"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	HEADERS_X_PUBLIC    = "X-Public"
	HEADERS_X_CLIENT_ID = "X-Client-Id"
	HEADERS_X_CALLER_ID = "X-Caller-Id"

	PARAMS_ACCESS_TOKEN = "access_token"

	OAUTH_API_BASE_URL                        = "http://localhost:3000%s"
	OAUTH_API_OAUTH_ACCESS_TOKEN_GET_ENDPOINT = "/oauth/access_token/%s"
)

type oAuthClient struct {
}

type oAuthInterface interface {
}

type accessToken struct {
	AccessToken string `json:"accessToken"`
	UserID      string `json:"userId"`
	ClientID    string `json:"clientId"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(HEADERS_X_PUBLIC) == "true"
}

func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(HEADERS_X_CALLER_ID), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(request.Header.Get(HEADERS_X_CLIENT_ID), 10, 64)
	if err != nil {
		return 0
	}

	return clientId
}

func AuthenticateRequest(request *http.Request) *errors_utils.APIError {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	at := strings.TrimSpace(request.URL.Query().Get(PARAMS_ACCESS_TOKEN))
	if at == "" {
		return nil
	}

	getAccessTokenResponse, getAccessTokenErr := getAccessToken(at)
	if getAccessTokenErr != nil {
		return getAccessTokenErr
	}

	request.Header.Add(HEADERS_X_CLIENT_ID, fmt.Sprintf("%v", getAccessTokenResponse.ClientID))
	request.Header.Add(HEADERS_X_CALLER_ID, fmt.Sprintf("%v", getAccessTokenResponse.UserID))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(HEADERS_X_CLIENT_ID)
	request.Header.Del(HEADERS_X_CALLER_ID)
}

func getAccessToken(at string) (*accessToken, *errors_utils.APIError) {
	client := http_client.GetHTTPClient()

	endpoint := fmt.Sprintf(OAUTH_API_OAUTH_ACCESS_TOKEN_GET_ENDPOINT, at)
	url := fmt.Sprintf(OAUTH_API_BASE_URL, endpoint)

	resp, err := client.R().
		EnableTrace().
		SetHeader("Accept", "application/json").
		Get(url)
	if err != nil {
		return nil, &errors_utils.APIError{
			Status:  http.StatusInternalServerError,
			Message: "unable to get access token",
		}
	}
	body := resp.Body()

	if resp.StatusCode() > 299 {
		var apiErr errors_utils.APIError
		if body != nil {
			err := json.Unmarshal(body, &apiErr)
			if err != nil {
				return nil, &errors_utils.APIError{
					Status:  http.StatusInternalServerError,
					Message: "invalid error response when getting access token",
				}
			}
			s := string(body)
			fmt.Println(s) // ABC€
			return nil, &apiErr
		}
	}

	var foundAccessToken accessToken
	if err := json.Unmarshal(body, &foundAccessToken); err != nil {
		return nil, &errors_utils.APIError{
			Status:  http.StatusInternalServerError,
			Message: "error when trying to unmarshal access token data",
		}
	}

	return &foundAccessToken, nil
}
