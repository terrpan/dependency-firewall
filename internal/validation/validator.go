package validation

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// New creates a validator configured for the given struct tag name.
func New(tagName string) *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	v.RegisterValidation("notblank", notBlank)

	if tagName != "" {
		v.RegisterTagNameFunc(func(field reflect.StructField) string {
			name := strings.Split(field.Tag.Get(tagName), ",")[0]
			if name == "" || name == "-" {
				return field.Name
			}
			return name
		})
	}

	return v
}

// ErrorMessage returns the first validation error as a user-facing message.
func ErrorMessage(err error) string {
	if err == nil {
		return ""
	}

	var invalidErr *validator.InvalidValidationError
	if errors.As(err, &invalidErr) {
		return invalidErr.Error()
	}

	var validationErrs validator.ValidationErrors
	if !errors.As(err, &validationErrs) || len(validationErrs) == 0 {
		return err.Error()
	}

	return fieldErrorMessage(validationErrs[0])
}

func notBlank(fl validator.FieldLevel) bool {
	field, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}
	return strings.TrimSpace(field) != ""
}

func fieldErrorMessage(fe validator.FieldError) string {
	field := fieldPath(fe)

	switch fe.Tag() {
	case "required", "notblank":
		return fmt.Sprintf("field %q is required", field)
	case "oneof":
		return fmt.Sprintf("field %q must be one of [%s]", field, fe.Param())
	case "url":
		return fmt.Sprintf("field %q must be a valid URL", field)
	case "gt":
		return fmt.Sprintf("field %q must be greater than %s", field, fe.Param())
	case "gte":
		return fmt.Sprintf("field %q must be greater than or equal to %s", field, fe.Param())
	case "lt":
		return fmt.Sprintf("field %q must be less than %s", field, fe.Param())
	case "lte":
		return fmt.Sprintf("field %q must be less than or equal to %s", field, fe.Param())
	default:
		return fmt.Sprintf("field %q is invalid", field)
	}
}

func fieldPath(fe validator.FieldError) string {
	namespace := fe.Namespace()
	if namespace == "" {
		return fe.Field()
	}

	parts := strings.Split(namespace, ".")
	if len(parts) <= 1 {
		return namespace
	}

	return strings.Join(parts[1:], ".")
}
