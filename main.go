package main

import (
	"context"
	"fmt"

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
	fmt.Printf("wndc=%#v\n", wndc)
	fmt.Printf("Username = %s\nPassword = %s\n", wndc.ProxyUsername, wndc.ProxyPassword)
}
