// nolint: revive
// Package unifi provides a set of types to unload (unmarshal) Ubiquiti UniFi
// controller data. Also provided are methods to easily get data for devices -
// things like access points and switches, and for clients - the things
// connected to those access points and switches. As a bonus, each device and
// client type provided has an attached method to create InfluxDB datapoints.
package protect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

var (
	ErrAuthenticationFailed = fmt.Errorf("authentication failed")
	ErrInvalidStatusCode    = fmt.Errorf("invalid status code from server")
	ErrNoParams             = fmt.Errorf("requested PUT with no parameters")
	ErrInvalidSignature     = fmt.Errorf("certificate signature does not match")
)

// NewUnifi creates a http.Client with authenticated cookies.
// Used to make additional, authenticated requests to the APIs.
// Start here.
func NewClient(config *Config) (*Unifi, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("creating cookiejar: %w", err)
	}

	u := newUnifi(config, jar)

	for i, cert := range config.SSLCert {
		p, _ := pem.Decode(cert)
		u.fingerprints[i] = fmt.Sprintf("%x", sha256.Sum256(p.Bytes))
	}

	if err := u.checkNewStyleAPI(); err != nil {
		return u, err
	}

	if err := u.Login(); err != nil {
		return u, err
	}

	return u, nil
}

func newUnifi(config *Config, jar http.CookieJar) *Unifi {
	config.URL = strings.TrimRight(config.URL, "/")

	if config.ErrorLog == nil {
		config.ErrorLog = discardLogs
	}

	if config.DebugLog == nil {
		config.DebugLog = discardLogs
	}

	u := &Unifi{
		Config: config,
		Client: &http.Client{
			Timeout: config.Timeout,
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: !config.VerifySSL, // nolint: gosec
				},
			},
		},
	}

	if len(config.SSLCert) > 0 {
		u.fingerprints = make(fingerprints, len(config.SSLCert))
		u.Client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify:    true, // nolint: gosec
				VerifyPeerCertificate: u.verifyPeerCertificate,
			},
		}
	}

	return u
}

func (u *Unifi) verifyPeerCertificate(certs [][]byte, _ [][]*x509.Certificate) error {
	if len(u.fingerprints) == 0 {
		return nil
	}

	for _, cert := range certs {
		if u.fingerprints.Contains(fmt.Sprintf("%x", sha256.Sum256(cert))) {
			return nil
		}
	}

	return ErrInvalidSignature
}

// Login is a helper method. It can be called to grab a new authentication cookie.
func (u *Unifi) Login() error {
	start := time.Now()

	// magic login.
	req, err := u.UniReq(APILoginPath, fmt.Sprintf(`{"username":"%s","password":"%s"}`, u.User, u.Pass))
	if err != nil {
		return err
	}

	resp, err := u.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}

	defer resp.Body.Close()               // we need no data here.
	_, _ = io.Copy(io.Discard, resp.Body) // avoid leaking.
	u.DebugLog("Requested %s: elapsed %v, returned %d bytes",
		req.URL, time.Since(start).Round(time.Millisecond), resp.ContentLength)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("(user: %s): %s (status: %s): %w",
			u.User, req.URL, resp.Status, ErrAuthenticationFailed)
	}

	return nil
}

// Logout closes the current session.
func (u *Unifi) Logout() error {
	// a post is needed for logout
	_, err := u.PostJSON(APILogoutPath)

	return err
}

// with the release of controller version 5.12.55 on UDM in Jan 2020 the api paths
// changed and broke this library. This function runs when `NewUnifi()` is called to
// check if this is a newer controller or not. If it is, we set new to true.
// Setting new to true makes the path() method return different (new) paths.
func (u *Unifi) checkNewStyleAPI() error {
	var (
		ctx    = context.Background()
		cancel func()
	)

	if u.Config.Timeout != 0 {
		ctx, cancel = context.WithTimeout(ctx, u.Config.Timeout)
		defer cancel()
	}

	u.DebugLog("Requesting %s/ to determine API paths", u.URL)

	req, err := http.NewRequestWithContext(ctx, "GET", u.URL+"/", nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	// We can't share these cookies with other requests, so make a new client.
	// Checking the return code on the first request so don't follow a redirect.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !u.VerifySSL}, // nolint: gosec
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}

	defer resp.Body.Close()               // we need no data here.
	_, _ = io.Copy(io.Discard, resp.Body) // avoid leaking.

	if resp.StatusCode == http.StatusOK {
		// The new version returns a "200" for a / request.
		u.new = true
		u.DebugLog("Using NEW UniFi controller API paths for %s", req.URL)
	}

	// The old version returns a "302" (to /manage) for a / request
	return nil
}

// GetData makes a unifi request and unmarshals the response into a provided pointer.
func (u *Unifi) GetData(apiPath string, v interface{}, params ...string) error {
	start := time.Now()

	body, err := u.GetJSON(apiPath, params...)
	if err != nil {
		return err
	}

	u.DebugLog("Requested %s: elapsed %v, returned %d bytes",
		u.URL+u.path(apiPath), time.Since(start).Round(time.Millisecond), len(body))

	return json.Unmarshal(body, v)
}

// GetData makes a unifi request and unmarshals the response into a provided pointer.
func (u *Unifi) GetRaw(apiPath string, params ...string) ([]byte, error) {
	start := time.Now()

	body, err := u.GetJSON(apiPath, params...)
	if err != nil {
		return nil, err
	}

	u.DebugLog("Requested %s: elapsed %v, returned %d bytes",
		u.URL+u.path(apiPath), time.Since(start).Round(time.Millisecond), len(body))

	return body, nil
}

// PutData makes a unifi request and unmarshals the response into a provided pointer.
func (u *Unifi) PutData(apiPath string, v interface{}, params ...string) error {
	start := time.Now()

	body, err := u.PutJSON(apiPath, params...)
	if err != nil {
		return err
	}

	u.DebugLog("Requested %s: elapsed %v, returned %d bytes",
		u.URL+u.path(apiPath), time.Since(start).Round(time.Millisecond), len(body))

	return json.Unmarshal(body, v)
}

// UniReq is a small helper function that adds an Accept header.
// Use this if you're unmarshalling UniFi data into custom types.
// And if you're doing that... sumbut a pull request with your new struct. :)
// This is a helper method that is exposed for convenience.
func (u *Unifi) UniReq(apiPath string, params string) (*http.Request, error) {
	var (
		req *http.Request
		err error
	)

	switch apiPath = u.path(apiPath); params {
	case "":
		req, err = http.NewRequest(http.MethodGet, u.URL+apiPath, nil)
	default:
		req, err = http.NewRequest(http.MethodPost, u.URL+apiPath, bytes.NewBufferString(params))
	}

	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	u.setHeaders(req, params)

	return req, nil
}

// UniReqPut is the Put call equivalent to UniReq.
func (u *Unifi) UniReqPut(apiPath string, params string) (*http.Request, error) {
	if params == "" {
		return nil, ErrNoParams
	}

	apiPath = u.path(apiPath)

	req, err := http.NewRequest(http.MethodPut, u.URL+apiPath, bytes.NewBufferString(params)) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	u.setHeaders(req, params)

	return req, nil
}

// UniReqPost is the Post call equivalent to UniReq.
func (u *Unifi) UniReqPost(apiPath string, params string) (*http.Request, error) {
	apiPath = u.path(apiPath)

	req, err := http.NewRequest(http.MethodPost, u.URL+apiPath, bytes.NewBufferString(params)) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	u.setHeaders(req, params)

	return req, nil
}

// GetJSON returns the raw JSON from a path. This is useful for debugging.
func (u *Unifi) GetJSON(apiPath string, params ...string) ([]byte, error) {
	req, err := u.UniReq(apiPath, strings.Join(params, " "))
	if err != nil {
		return []byte{}, err
	}

	return u.do(req)
}

// PutJSON uses a PUT call and returns the raw JSON in the same way as GetData
// Use this if you want to change data via the REST API.
func (u *Unifi) PutJSON(apiPath string, params ...string) ([]byte, error) {
	req, err := u.UniReqPut(apiPath, strings.Join(params, " "))
	if err != nil {
		return []byte{}, err
	}

	return u.do(req)
}

// PostJSON uses a POST call and returns the raw JSON in the same way as GetData
// Use this if you want to change data via the REST API.
func (u *Unifi) PostJSON(apiPath string, params ...string) ([]byte, error) {
	req, err := u.UniReqPost(apiPath, strings.Join(params, " "))
	if err != nil {
		return []byte{}, err
	}

	return u.do(req)
}

func (u *Unifi) do(req *http.Request) ([]byte, error) {
	var (
		cancel func()
		ctx    = context.Background()
	)

	if u.Config.Timeout != 0 {
		ctx, cancel = context.WithTimeout(ctx, u.Config.Timeout)
		defer cancel()
	}

	resp, err := u.Do(req.WithContext(ctx))
	if err != nil {
		return []byte{}, fmt.Errorf("making request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return body, fmt.Errorf("reading response: %w", err)
	}

	// Save the returned CSRF header.
	if csrf := resp.Header.Get("x-csrf-token"); csrf != "" {
		u.csrf = resp.Header.Get("x-csrf-token")
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s: %s: %w", req.URL, resp.Status, ErrInvalidStatusCode)
	}

	return body, err
}

func (u *Unifi) setHeaders(req *http.Request, params string) {
	// Add the saved CSRF header.
	req.Header.Set("X-CSRF-Token", u.csrf)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	if u.Client.Jar != nil {
		parsedURL, _ := url.Parse(req.URL.String())
		u.DebugLog("Requesting %s, with params: %v, cookies: %d", req.URL, params != "", len(u.Client.Jar.Cookies(parsedURL)))
	} else {
		u.DebugLog("Requesting %s, with params: %v,", req.URL, params != "")
	}
}

func (u *Unifi) GetCameras() ([]*Camera, error) {
	start := time.Now()

	var data []*Camera

	err := u.GetData("/api/cameras", &data)
	if err != nil {
		return nil, err
	}

	u.DebugLog("Requested %s: elapsed %v",
		u.URL+u.path("/api/cameras"), time.Since(start).Round(time.Millisecond))

	return data, nil
}

func (u *Unifi) GetCameraByID(value string) (*Camera, error) {
	cameras, err := u.GetCameras()
	if err != nil {
		return nil, err
	}

	for _, camera := range cameras {
		if camera.ID == value {
			return camera, nil
		}
	}

	return nil, fmt.Errorf("Camera with id \"%s\" not found", value)
}

// Acutally retreived by "displayName", in testing "name" was not always present (null value) while "displayName" always was. If it was present they were always identitcal.
func (u *Unifi) GetCameraByName(value string) (*Camera, error) {
	cameras, err := u.GetCameras()
	if err != nil {
		return nil, err
	}

	for _, camera := range cameras {
		if camera.Name == value {
			return camera, nil
		}
	}

	return nil, fmt.Errorf("Camera with id \"%s\" not found", value)
}

// Prepare and download a clip from the specified camera for the time window. In testing, the prepare API can be overloaded
// and will start throwing 500 errors. Two other major errors yet to be understood exist. The first relates to the length of
// the clip, sometimes the clip is either shorter or longer than the specified time. The second has to do with requesting
// clips from time periods too close to "now", Unifi will return 500 if this is the case.
func (u *Unifi) GetClipBytes(cameraID string, start, end time.Time) ([]byte, error) {
	var prepValues = url.Values{}

	prepValues.Set("camera", cameraID)
	prepValues.Set("start", strconv.FormatInt(start.UnixMilli(), 10))
	prepValues.Set("end", strconv.FormatInt(end.UnixMilli(), 10))
	prepValues.Set("channel", "0")
	prepValues.Set("lens", "0")
	prepValues.Set("type", "rotating")
	prepValues.Set("filename", fmt.Sprintf("%s_%s-%s.mp4", prepValues.Get("camera"), prepValues.Get("start"), prepValues.Get("end")))

	// Prepare Clip Download
	var responsePrep interface{}

	prepClipURL := "/api/video/prepare?" + prepValues.Encode()

	err := u.GetData(prepClipURL, &responsePrep)
	if err != nil {
		return nil, err
	}

	// Download Clip
	var responseDownload []byte

	var downloadValues = url.Values{}

	downloadValues.Set("camera", prepValues.Get("camera"))
	downloadValues.Set("filename", prepValues.Get("filename"))

	downloadClipURL := "/api/video/download?" + downloadValues.Encode()

	responseDownload, err = u.GetRaw(downloadClipURL)
	if err != nil {
		return nil, err
	}

	return responseDownload, nil
}

// Prepare and download a clip from the specified camera for the time window then return a temp file where it's located.
// See GetClipBytes for more.
func (u *Unifi) DownloadClip(cameraID string, start, end time.Time) (*os.File, error) {
	clipBytes, err := u.GetClipBytes(cameraID, start, end)
	if err != nil {
		return nil, err
	}

	f, err := os.CreateTemp("", cameraID)
	if err != nil {
		return nil, err
	}

	_, err = f.Write(clipBytes)
	if err != nil {
		return nil, err
	}

	return f, nil
}
