// Copyright 2025 The Alpaca Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	ring "github.com/zalando/go-keyring"
	"golang.org/x/term"
)

// basicFromKeyring loads the Basic proxy password for user from the OS
// keyring under service. If the entry is missing and prompt is non-nil,
// the password is read via prompt and stored. On a later 407 the entry
// is deleted and the authenticator stops offering credentials, so a
// stale password cannot lock the directory account.
func basicFromKeyring(service, user string, prompt func() (string, error)) (*basicAuthenticator, error) {
	pw, err := ring.Get(service, user)
	if errors.Is(err, ring.ErrNotFound) && prompt != nil {
		pw, err = prompt()
		if err != nil {
			return nil, err
		}
		if pw == "" {
			return nil, errors.New("empty password")
		}
		if err := ring.Set(service, user, pw); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("keyring service %q user %q: %w", service, user, err)
	}
	b := newBasicAuthenticator(user + ":" + pw)
	b.onReject = func() {
		derr := ring.Delete(service, user)
		log.Printf("Basic credentials for %s were rejected (407); deleted keyring entry service=%q and stopped sending Basic. Store the new password with: security add-generic-password -U -s %s -a %s -w ; then restart alpaca", user, service, service, user)
		if derr != nil {
			log.Printf("Deleting keyring entry service=%q user=%q failed: %v", service, user, derr)
		}
	}
	return b, nil
}

// terminalPasswordPrompt returns a prompt reading the password from the
// terminal, or nil when stdin is not a terminal.
func terminalPasswordPrompt(user string) func() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}
	return func() (string, error) {
		fmt.Printf("Proxy password (for %s): ", user)
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return string(pw), err
	}
}
