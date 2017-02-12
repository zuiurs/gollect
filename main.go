package main

import (
	"flag"
	"fmt"
	"github.com/zuiurs/gollect/oauth1"
	"os"
)

var (
	settingFileName string
)

const (
	SignatureMethod = "HMAC-SHA1"
	OAuthVersion    = "1.0"
	CallbackURL     = "oob"
	RequestTokenURL = "https://api.twitter.com/oauth/request_token"
	AccessTokenURL  = "https://api.twitter.com/oauth/access_token"
	AuthorizeURL    = "https://api.twitter.com/oauth/authorize"
)

func main() {
	flag.StringVar(&settingFileName, "s", "-", "application setting filename")
	flag.Parse()

	f, err := os.Open(settingFileName)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()

	oauth := &oauth1.OAuth{
		OAuthVersion:         OAuthVersion,
		OAuthCallbackURL:     CallbackURL,
		OAuthSignatureMethod: SignatureMethod,
		RequestTokenURL:      RequestTokenURL,
		AccessTokenURL:       AccessTokenURL,
		AuthorizeURL:         AuthorizeURL,
	}
	err = oauth.OAuthParseJson(f)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}

	reqToken, callbackURL, err := oauth.GetRequestTokenAndURL()
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("Authorize URL: %s\n", callbackURL)
	fmt.Printf("Enter PIN: ")
	var pin string
	fmt.Scan(&pin)
	oauth.OAuthVerifier = pin

	accToken, err := oauth.GetAccessToken(reqToken)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
	oauth.AccessToken = accToken
	fmt.Println("%#v\n", accToken)
}
