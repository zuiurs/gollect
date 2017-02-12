// Twitter API package in command-line environment

package twitter

import (
	"fmt"
	"github.com/zuiurs/gollect/oauth1"
)

const (
	SignatureMethod = "HMAC-SHA1"
	OAuthVersion    = "1.0"
	CallbackURL     = "oob"
	RequestTokenURL = "https://api.twitter.com/oauth/request_token"
	AccessTokenURL  = "https://api.twitter.com/oauth/access_token"
	AuthorizeURL    = "https://api.twitter.com/oauth/authorize"
)

type Twitter struct {
	*oauth1.OAuth
	Username string
}

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
