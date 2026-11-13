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
	"encoding/base64"
	"net/http"
	"sync/atomic"
)

type basicAuthenticator struct {
	encoded  string
	onReject func()
	rejected atomic.Bool
}

func newBasicAuthenticator(credentials string) *basicAuthenticator {
	return &basicAuthenticator{
		encoded: base64.StdEncoding.EncodeToString([]byte(credentials)),
	}
}

func (b *basicAuthenticator) scheme() string { return "Basic" }

// applicableTo has no host policy, but declines once the stored credential
// has been rejected by the proxy (407).
func (b *basicAuthenticator) applicableTo(string) bool { return !b.rejected.Load() }

func (b *basicAuthenticator) do(req *http.Request, rt http.RoundTripper) (*http.Response, error) {
	req.Header.Set("Proxy-Authorization", "Basic "+b.encoded)
	resp, err := rt.RoundTrip(req)
	if err == nil && resp.StatusCode == http.StatusProxyAuthRequired &&
		b.onReject != nil && b.rejected.CompareAndSwap(false, true) {
		b.onReject()
	}
	return resp, err
}
