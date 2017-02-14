package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/zuiurs/gollect/twitter"
	"io"
	"log"
	"os"
)

var (
	settingFileName string
)

func main() {
	flag.StringVar(&settingFileName, "s", "-", "application setting filename")
	flag.Parse()

	f, err := os.Open(settingFileName)
	if err != nil {
		log.Fatal("failed to open the file:", err)
	}
	defer f.Close()

	key, secret, err := OAuthSettingParseJSON(f)
	if err != nil {
		log.Fatal("failed to parse json:", err)
	}

	t, err := twitter.Authorize(key, secret)
	if err != nil {
		log.Fatal("failed to authorize the client:", err)
	}

	fmt.Println("%#v\n", t.AccessToken)
}

// OAuthSettingParseJSON parses JSON data r,
// and returns ConsumerKey and ConsumerSecret values.
// r should contain below parameters.
// - consumer_key
// - consumer_secret
func OAuthSettingParseJSON(r io.Reader) (string, string, error) {
	dec := json.NewDecoder(r)

	var oauthSetting struct {
		ConsumerKey    string `json:"consumer_key"`
		ConsumerSecret string `json:"consumer_secret"`
	}

	if err := dec.Decode(&oauthSetting); err != nil {
		return "", "", err
	}

	return oauthSetting.ConsumerKey, oauthSetting.ConsumerSecret, nil
}
