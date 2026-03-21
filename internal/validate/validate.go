package validate

import (
	"fmt"

	"github.com/go-playground/validator/v10"

	sdkvalidate "github.com/manchtools/power-manage/sdk/go/validate"
)

// validate is the shared validator instance with ULID custom rule.
var validate *validator.Validate

func init() {
	validate = sdkvalidate.NewValidator()
}

// Struct validates a struct using the go-playground validator.
func Struct(v any) error {
	msg, ok := sdkvalidate.Struct(validate, v)
	if !ok {
		return fmt.Errorf("%s", msg)
	}
	return nil
}
