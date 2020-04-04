package aksk_auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAKSKAuthForRealm(t *testing.T) {
	router := gin.Default()
	accounts := map[string][]byte{"123": []byte("123")}
	router.Use(AKSKAuthForRealm(accounts, "test"))

	router.POST("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	router.Run(":4096")

}

func TestAKSKBasicAuth(t *testing.T) {
	requestBody := `{
		"name:":"张三",
		"age":18
	}`
	reader := bytes.NewBufferString(requestBody)
	request, err := http.NewRequest(http.MethodPost, "http://localhost:4096/ping?name=张三&age=18", reader)
	if err != nil {
		t.Error(err)
		return
	}

	// 构造验证数据
	signContent := bytes.NewBufferString(fmt.Sprintln("POST /ping?name=张三&age=18"))
	signContent.WriteString(fmt.Sprintln("Host: localhost:4096"))
	signContent.WriteString(fmt.Sprintln("Content-Type: application/json"))
	signContent.WriteString(fmt.Sprintln())
	signContent.WriteString(requestBody)

	// 签名
	mm := hmac.New(sha1.New, []byte("123"))
	mm.Write(signContent.Bytes())
	signed := base64.URLEncoding.EncodeToString(mm.Sum(nil))

	// 添加签名
	authorization := "test 123:" + signed
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Error(err)
		return
	}

	if response.StatusCode != http.StatusOK {
		t.Errorf("invalid code: %v", response.StatusCode)
		return
	}

	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("err: ", err.Error())
		return
	}
	fmt.Println("result：", string(respBody))
}

func TestAKSKAuthForRealm2(t *testing.T) {
	t.Log(hmac.Equal([]byte("11"), []byte("11")))
}
