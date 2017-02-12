package oauth1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// PhaseRequestToken shows this phase is OAuth Request Token
	PhaseRequestToken Phase = 1 << iota
	// PhaseAccessToken shows this phase is OAuth Access Token
	PhaseAccessToken
	// PhaseAuthorized shows this phase is after authorized your Twitter client.
	PhaseAuthorized
)

// Phase shows levels of OAuth request phase.
type Phase int

// OAuth has some OAuth parameters required in OAuth request phase.
type OAuth struct {
	//------- required Pre-fill -------
	ConsumerKey    string `json:"consumer_key"`
	ConsumerSecret string `json:"consumer_secret"`

	OAuthSignatureMethod string
	OAuthCallbackURL     string
	OAuthVersion         string

	RequestTokenURL string
	AccessTokenURL  string
	AuthorizeURL    string
	//---------------------------------

	OAuthVerifier string
	*AccessToken
}

// OAuthTokenSet has a set of token.
// This set given by OAuth provider.
type OAuthTokenSet struct {
	OAuthToken       string
	OAuthTokenSecret string
}

// TODO: Standardize RequestToken and AccessToken
//       to OAuthTokenSet for generateAuthHeaderParam function.

// RequestToken is wrapped struct of OAuthTokenSet.
// This is used in RequestToken phase.
type RequestToken OAuthTokenSet

// AccessToken is wrapped struct of OAuthTokenSet.
// This is used in AccessToken phase.
type AccessToken OAuthTokenSet

// GetRequestTokenAndURL gets RequestToken and CallbackURL
// based on oauth instance's parameters.
// If you set "oob" on CallbackURL,
// then returned CallbackURL will be AuthorizeURL.
func (oauth *OAuth) GetRequestTokenAndURL() (*RequestToken, string, error) {
	endp := oauth.RequestTokenURL
	method := "POST"

	// build custom HTTP request
	req, err := http.NewRequest(method, endp, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Add("Authorization",
		oauth.generateAuthHeaderParam(
			endp,
			method,
			"",
			"",
			PhaseRequestToken,
		),
	)

	// send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}

	// parse response
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	// [Response Sample]
	// oauth_token=V1E_NQAAAAAAyK11AAABWiJ2k3A&oauth_token_secret=xjth5du2YyLhFAKrkqNkpWtKLehNFqRr&oauth_callback_confirmed=true
	rvalues, err := url.ParseQuery(string(b))
	if err != nil {
		return nil, "", err
	}
	if rvalues.Get("oauth_callback_confirmed") != "true" {
		return nil, "", fmt.Errorf("Callback URL was not confirmed")
	}

	reqToken := RequestToken{
		OAuthToken:       rvalues.Get("oauth_token"),
		OAuthTokenSecret: rvalues.Get("oauth_token_secret"),
	}

	// build callback URL
	callbackURL := oauth.OAuthCallbackURL
	if callbackURL == "oob" {
		// PIN based OAuth
		callbackURL = oauth.AuthorizeURL
	}
	callbackURL += "?oauth_token=" + reqToken.OAuthToken

	return &reqToken, callbackURL, nil
}

// GetAccessToken gets AccessToken based on oauth instance's parameters.
// TODO: Return values contain user_id and screen_name. (Approach: make hashmap for other param)
func (oauth *OAuth) GetAccessToken(reqToken *RequestToken) (*AccessToken, error) {
	endp := oauth.AccessTokenURL
	method := "POST"

	// build custom HTTP request
	req, err := http.NewRequest(method, endp, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization",
		oauth.generateAuthHeaderParam(
			endp,
			method,
			reqToken.OAuthToken,
			reqToken.OAuthTokenSecret,
			PhaseAccessToken,
		),
	)

	// send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	// parse response
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// [Response Sample]
	// oauth_token=6253282-eWudHldSbIaelX7swmsiHImEL4KinwaGloHANdrY&oauth_token_secret=2EEfA6BG3ly3sR3RjE0IBSnlQu4ZrUzPiYKmrkVU&user_id=6253282&screen_name=twitterapi
	rvalues, err := url.ParseQuery(string(b))
	if err != nil {
		return nil, err
	}

	accToken := AccessToken{
		OAuthToken:       rvalues.Get("oauth_token"),
		OAuthTokenSecret: rvalues.Get("oauth_token_secret"),
	}

	return &accToken, nil
}

// generateAuthHeaderParam returns Authorization Header value.
func (oauth *OAuth) generateAuthHeaderParam(reqURL, method, token, tokenSecret string, phase Phase) string {
	values := url.Values{}
	values.Set("oauth_consumer_key", oauth.ConsumerKey)
	values.Add("oauth_nonce", RandStringRunes(32))
	values.Add("oauth_signature_method", oauth.OAuthSignatureMethod)
	values.Add("oauth_timestamp", strconv.Itoa(int(time.Now().Unix())))
	values.Add("oauth_version", oauth.OAuthVersion)
	if phase&PhaseRequestToken != 0 {
		values.Add("oauth_callback", oauth.OAuthCallbackURL)
	}
	if phase&PhaseAccessToken != 0 {
		values.Add("oauth_verifier", oauth.OAuthVerifier)
	}
	if phase&(PhaseAccessToken|PhaseAuthorized) != 0 {
		values.Add("oauth_token", token)
	}

	// build signature base string as data
	requestElem := []string{method, reqURL, values.Encode()}
	var signatureBaseString string
	for i, s := range requestElem {
		if i == 0 {
			signatureBaseString += url.QueryEscape(s)
		} else {
			signatureBaseString += "&" + url.QueryEscape(s)
		}
	}

	key := url.QueryEscape(oauth.ConsumerSecret) + "&" + url.QueryEscape(tokenSecret)

	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(signatureBaseString))

	values.Add("oauth_signature", base64.StdEncoding.EncodeToString(h.Sum(nil)))

	// build Authorization header parameter
	authParam := "OAuth "
	for k, v := range values {
		authParam += url.QueryEscape(k) + "=\"" + url.QueryEscape(v[0]) + "\", "
	}

	return strings.TrimSuffix(authParam, ", ")
}
