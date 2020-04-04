package aksk_auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"
)

const (
	maxContentLength = 1 << 20 // 1MB
)

func signRequest(secretKey []byte, signed string, req *http.Request) bool {
	h := hmac.New(sha1.New, secretKey)
	content := bytes.NewBuffer(nil)
	u := req.URL

	content.WriteString(req.Method + " " + u.Path)
	if u.RawQuery != "" {
		content.WriteString("?" + u.RawQuery)
	}
	content.WriteString("\nHost: " + req.Host)

	ctType := req.Header.Get("Content-Type")
	if ctType != "" {
		content.WriteString("\nContent-Type: " + ctType)
	}
	content.WriteString("\n\n")

	if incBody(req, ctType) {
		body, er := ioutil.ReadAll(req.Body)
		if er != nil {
			return false
		}

		content.Write(body)
		req.Body = &readCloser{
			Reader: bytes.NewReader(body),
			Closer: req.Body,
		}
	}
	h.Write(content.Bytes())
	return hmac.Equal([]byte(signed), []byte(base64.URLEncoding.EncodeToString(h.Sum(nil))))
}

func incBody(req *http.Request, ctType string) bool {
	typeOk := ctType != "" && ctType != "application/octet-stream"
	lengthOk := req.ContentLength > 0 && req.ContentLength < maxContentLength
	return typeOk && lengthOk && req.Body != nil
}

type readCloser struct {
	io.Reader
	io.Closer
}
