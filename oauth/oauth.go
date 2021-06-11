package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	http_client "github.com/bRRRITSCOLD/bookstore_oauth-go/oauth-clients/http"
	errors_utils "github.com/bRRRITSCOLD/bookstore_utils-go/errors"
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
	UserID      int64  `json:"userId"`
	ClientID    int64  `json:"clientId"`
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

func AuthenticateRequest(request *http.Request) errors_utils.APIError {
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
		if getAccessTokenErr.Status() == http.StatusNotFound {
			return nil
		}
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

func getAccessToken(at string) (*accessToken, errors_utils.APIError) {
	client := http_client.GetHTTPClient()

	endpoint := fmt.Sprintf(OAUTH_API_OAUTH_ACCESS_TOKEN_GET_ENDPOINT, at)
	url := fmt.Sprintf(OAUTH_API_BASE_URL, endpoint)

	resp, err := client.R().
		EnableTrace().
		SetHeader("Accept", "application/json").
		Get(url)
	if err != nil {
		return nil, errors_utils.NewInternalServerAPIError("unable to get access token", nil)
	}
	body := resp.Body()

	if resp.StatusCode() > 299 {
		var apiErr errors_utils.APIError
		apiErr, err := errors_utils.NewAPIErrorFromBytes(body)
		if err != nil {
			return nil, errors_utils.NewInternalServerAPIError(
				"invalid error response when getting access token",
				err,
			)
		}
		return nil, apiErr
	}

	var foundAccessToken accessToken
	if err := json.Unmarshal(body, &foundAccessToken); err != nil {
		return nil, errors_utils.NewInternalServerAPIError(
			"error when trying to unmarshal access token data",
			err,
		)
	}

	return &foundAccessToken, nil
}
