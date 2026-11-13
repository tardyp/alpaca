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
	"net/http"
	"testing"

	ring "github.com/zalando/go-keyring"
)

type statusRT struct{ code int }

func (s statusRT) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: s.code, Body: http.NoBody, Request: req}, nil
}

func TestBasicFromKeyringSendsStoredCredential(t *testing.T) {
	ring.MockInit()
	if err := ring.Set("svc", "u", "p"); err != nil {
		t.Fatal(err)
	}
	b, err := basicFromKeyring("svc", "u", nil)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	if _, err := b.do(req, statusRT{200}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Proxy-Authorization"); got != "Basic dTpw" {
		t.Fatalf("Proxy-Authorization = %q", got)
	}
	if !b.applicableTo("x") {
		t.Fatal("applicableTo false after 200")
	}
}

func TestBasicFromKeyringDeletesOnRejection(t *testing.T) {
	ring.MockInit()
	if err := ring.Set("svc", "u", "p"); err != nil {
		t.Fatal(err)
	}
	b, err := basicFromKeyring("svc", "u", nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	inner := b.onReject
	b.onReject = func() { calls++; inner() }
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
		resp, err := b.do(req, statusRT{http.StatusProxyAuthRequired})
		if err != nil || resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("do: %v %v", resp, err)
		}
		if i == 0 {
			if _, err := ring.Get("svc", "u"); !errors.Is(err, ring.ErrNotFound) {
				t.Fatalf("entry not deleted: %v", err)
			}
			if b.applicableTo("x") {
				t.Fatal("applicableTo true after 407")
			}
		}
	}
	if calls != 1 {
		t.Fatalf("onReject ran %d times", calls)
	}
}

func TestBasicFromKeyringPromptsAndStores(t *testing.T) {
	ring.MockInit()
	if _, err := basicFromKeyring("svc", "u", func() (string, error) { return "p", nil }); err != nil {
		t.Fatal(err)
	}
	if pw, err := ring.Get("svc", "u"); err != nil || pw != "p" {
		t.Fatalf("Get = %q, %v", pw, err)
	}
	ring.MockInit()
	if _, err := basicFromKeyring("svc", "u", nil); !errors.Is(err, ring.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}
