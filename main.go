package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Snawoot/windscribe-proxy/wndclient"
)

func main() {
	wndc, err := wndclient.NewWndClient(nil)
	if err != nil {
		panic(err)
	}

	err = wndc.RegisterToken(context.TODO())
	if err != nil {
		panic(err)
	}

	err = wndc.Users(context.TODO())
	if err != nil {
		panic(err)
	}

	err = wndc.ServerCredentials(context.TODO())
	if err != nil {
		panic(err)
	}
	username, password := wndc.GetCredentials()
	fmt.Printf("Username = %s\nPassword = %s\n", username, password)

	list, err := wndc.ServerList(context.TODO())
	if err != nil {
		panic(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	err = enc.Encode(list)
	if err != nil {
		panic(err)
	}
}
