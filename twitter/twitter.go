// Twitter API package in command-line environment

package twitter

import (
	"fmt"
	"github.com/zuiurs/gollect/oauth1"
)

const (
	// SignatureMethod is method signing OAuth requests.
	SignatureMethod = "HMAC-SHA1"
	// OAuthVersion is varsion of OAuth.
	// Twitter Streaming API is only supported version 1.0a.
	OAuthVersion = "1.0"
	// CallbackURL is redirect URL to approve your client.
	// "oob" stands for out-of-band. This is used by PIN Based OAuth.
	CallbackURL = "oob"
	// RequestTokenURL is base URL of RequestToken phase.
	RequestTokenURL = "https://api.twitter.com/oauth/request_token"
	// AccessTokenURL is base URL of AccessToken phase.
	AccessTokenURL = "https://api.twitter.com/oauth/access_token"
	// AuthorizeURL is base URL of PIN Based OAuth's CallbackURL.
	AuthorizeURL = "https://api.twitter.com/oauth/authorize"
)

// Twitter is used to use Twitter API in this package.
type Twitter struct {
	*oauth1.OAuth
	Username string
}

// Authorize authorizes the Twitter client,
// shows by consumerKey and consumerSecret,
// and returns Twitter instance.
func Authorize(consumerKey, consumerSecret string) (*Twitter, error) {
	oauth := &oauth1.OAuth{
		ConsumerKey:          consumerKey,
		ConsumerSecret:       consumerSecret,
		OAuthVersion:         OAuthVersion,
		OAuthCallbackURL:     CallbackURL,
		OAuthSignatureMethod: SignatureMethod,
		RequestTokenURL:      RequestTokenURL,
		AccessTokenURL:       AccessTokenURL,
		AuthorizeURL:         AuthorizeURL,
	}

	reqToken, callbackURL, err := oauth.GetRequestTokenAndURL()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Authorize URL: %s\n", callbackURL)
	fmt.Printf("Enter PIN: ")
	var pin string
	fmt.Scan(&pin)
	oauth.OAuthVerifier = pin

	accToken, err := oauth.GetAccessToken(reqToken)
	if err != nil {
		return nil, err
	}
	oauth.AccessToken = accToken

	t := &Twitter{
		OAuth:    oauth,
		Username: "",
	}

	return t, nil
}
