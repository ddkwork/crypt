package hmac

import (
	"testing"

	"github.com/ddkwork/golibrary/stream"

	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {
	str := "appid=6442945423160112576"
	key := "adc2eb7f48928808adf27976b9e7091f"
	sha := New()
	hmacSha256 := sha.HmacSha256(str, stream.HexString(key))

	assert.Equal(t, stream.HexString("b5d095ac425352defc3d1af017181245fbf1000b002da21f32334a5e49f1844b"), hmacSha256.HexString())
	// assert.Equal(t, stream.HexString("6fd64b06f1f1a020a96e7b5181078e808fe262486efdb691698f7ab4a4489e6f"), hmacSha256.HexString())
}
