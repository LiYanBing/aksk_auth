package aksk_auth

import (
	"strings"

	"github.com/gin-gonic/gin"
)

type (
	Accounts map[string][]byte
	authPair struct {
		Key    string
		Secret []byte
	}
	authPairs []authPair
)

func (a authPairs) searchCredential(key string) ([]byte, bool) {
	if len(key) == 0 {
		return nil, false
	}

	for _, pair := range a {
		if pair.Key == key {
			return pair.Secret, true
		}
	}

	return nil, false
}

func AKSKBasicAuth(accounts Accounts) gin.HandlerFunc {
	return AKSKAuthForRealm(accounts, "")
}

func AKSKAuthForRealm(accounts Accounts, realm string) gin.HandlerFunc {
	if realm == "" {
		realm = "Basic"
	}
	pairs := processAccounts(accounts)

	return func(c *gin.Context) {
		authorization := c.Request.Header.Get("Authorization")
		if authorization == "" {
			c.AbortWithStatus(401)
			return
		}

		space := strings.IndexByte(authorization, ' ')
		if space == -1 {
			c.AbortWithStatus(401)
			return
		}

		colon := strings.IndexByte(authorization, ':')
		if colon == -1 {
			c.AbortWithStatus(401)
			return
		}

		if authorization[:space] != realm {
			c.AbortWithStatus(401)
			return
		}

		secretKey, ok := pairs.searchCredential(authorization[space+1 : colon])
		if !ok {
			c.AbortWithStatus(401)
			return
		}

		if !signRequest(secretKey, authorization[colon+1:], c.Request) {
			c.AbortWithStatus(401)
			return
		}
	}
}

func processAccounts(accounts Accounts) authPairs {
	pairs := make(authPairs, 0, len(accounts))
	for key, secret := range accounts {
		pairs = append(pairs, authPair{
			Key:    key,
			Secret: secret,
		})
	}
	return pairs
}
