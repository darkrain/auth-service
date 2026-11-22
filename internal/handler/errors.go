package handler

import (
	"github.com/darkrain/auth-service/internal/service"
	"github.com/gin-gonic/gin"
)

// Error codes for API responses
const (
	CodeInvalidRequest       = "ERR_INVALID_REQUEST"
	CodeInvalidEmail         = "ERR_INVALID_EMAIL"
	CodeInvalidPhone         = "ERR_INVALID_PHONE"
	CodeInvalidCredentials   = "ERR_INVALID_CREDENTIALS"
	CodeUserNotFound         = "ERR_USER_NOT_FOUND"
	CodeLoginExists          = "ERR_LOGIN_EXISTS"
	CodeNotVerified          = "ERR_NOT_VERIFIED"
	CodeBanned               = "ERR_BANNED"
	CodeDeleted              = "ERR_DELETED"
	CodeRoleReserved         = "ERR_ROLE_RESERVED"
	CodeRoleInvalid          = "ERR_ROLE_INVALID"
	CodePasswordTooShort     = "ERR_PASSWORD_TOO_SHORT"
	CodePasswordTooLong      = "ERR_PASSWORD_TOO_LONG"
	Code2FARequired          = "ERR_2FA_REQUIRED"
	CodeCodeInvalid          = "ERR_CODE_INVALID"
	CodeCodeNotFound         = "ERR_CODE_NOT_FOUND"
	CodeRecipientMismatch    = "ERR_RECIPIENT_MISMATCH"
	CodeTooManyRequests      = "ERR_TOO_MANY_REQUESTS"
	CodeAccountLocked        = "ERR_ACCOUNT_LOCKED"
	CodeUnauthorized         = "ERR_UNAUTHORIZED"
	CodeForbidden            = "ERR_FORBIDDEN"
	CodeInternal             = "ERR_INTERNAL"
	CodeRegistrationToken    = "ERR_REGISTRATION_TOKEN"
	CodeInvalidCode          = "ERR_INVALID_CODE"
	CodeCodeExpired          = "ERR_CODE_EXPIRED"
	CodeWeakPassword         = "ERR_WEAK_PASSWORD"
	CodeVerificationCooldown = "ERR_VERIFICATION_COOLDOWN"
	CodeConflict             = "ERR_CONFLICT"
)

// errResp returns a gin.H with error message and code
func errResp(code, message string) gin.H {
	return gin.H{"error": message, "code": code}
}

// passwordPolicyError is the response to a new password the password policy
// refused (service.ValidatePassword), the same at registration and reset:
// ERR_PASSWORD_TOO_SHORT, ERR_PASSWORD_TOO_LONG, or ERR_WEAK_PASSWORD for a
// configured complexity rule. ok is false for any other error.
func passwordPolicyError(err error) (response gin.H, ok bool) {
	var code string
	switch service.PasswordPolicyRule(err) {
	case "":
		return nil, false
	case service.PasswordRuleTooShort:
		code = CodePasswordTooShort
	case service.PasswordRuleTooLong:
		code = CodePasswordTooLong
	default:
		code = CodeWeakPassword
	}
	return errResp(code, err.Error()), true
}
