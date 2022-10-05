package hmac

import (
	"github.com/ddkwork/golibrary/mylog"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestName(t *testing.T) {
	key := "adc2eb7f48928808adf27976b9e7091f"
	str := "appid=6442945423160112576"
	sha := New()
	hmacSha256 := sha.HmacSha256(str, key)
	mylog.Success("String", hmacSha256.String())
	mylog.HexDump("Bytes", hmacSha256.Bytes())
	mylog.Success("EncodeToHexString", hmacSha256.HexString())
	assert.Equal(t, "6fd64b06f1f1a020a96e7b5181078e808fe262486efdb691698f7ab4a4489e6f", hmacSha256.HexString())
}
