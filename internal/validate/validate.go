package validate

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
)

// validate is the shared validator instance.
var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom ULID validator
	validate.RegisterValidation("ulid", validateULID)
}

// validateULID validates that a string is a valid ULID.
func validateULID(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := ulid.Parse(value)
	return err == nil
}

// Struct validates a struct using the go-playground validator.
func Struct(v any) error {
	if err := validate.Struct(v); err != nil {
		if validationErrors, ok := err.(validator.ValidationErrors); ok {
			return formatValidationErrors(validationErrors)
		}
		return err
	}
	return nil
}

// formatValidationErrors formats validation errors into a human-readable error.
func formatValidationErrors(errs validator.ValidationErrors) error {
	var messages []string
	for _, e := range errs {
		messages = append(messages, formatFieldError(e))
	}
	return fmt.Errorf("validation failed: %s", strings.Join(messages, "; "))
}

// formatFieldError formats a single field error into a human-readable message.
func formatFieldError(e validator.FieldError) string {
	field := toSnakeCase(e.Field())

	switch e.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "ulid":
		return fmt.Sprintf("%s must be a valid ULID", field)
	case "min":
		return fmt.Sprintf("%s must be at least %s", field, e.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s", field, e.Param())
	case "gte":
		return fmt.Sprintf("%s must be >= %s", field, e.Param())
	case "lte":
		return fmt.Sprintf("%s must be <= %s", field, e.Param())
	case "ne":
		return fmt.Sprintf("%s must not be %s", field, e.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, e.Param())
	default:
		return fmt.Sprintf("%s failed validation: %s", field, e.Tag())
	}
}

// toSnakeCase converts a PascalCase or camelCase string to snake_case.
func toSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteByte('_')
		}
		if r >= 'A' && r <= 'Z' {
			result.WriteRune(r + 32) // Convert to lowercase
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}
