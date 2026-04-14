package handler

import "github.com/gin-gonic/gin"

// Error codes for API responses
const (
	CodeInvalidRequest     = "ERR_INVALID_REQUEST"
	CodeInvalidEmail       = "ERR_INVALID_EMAIL"
	CodeInvalidPhone       = "ERR_INVALID_PHONE"
	CodeInvalidCredentials = "ERR_INVALID_CREDENTIALS"
	CodeUserNotFound       = "ERR_USER_NOT_FOUND"
	CodeLoginExists        = "ERR_LOGIN_EXISTS"
	CodeNotVerified        = "ERR_NOT_VERIFIED"
	CodeBanned             = "ERR_BANNED"
	CodeDeleted            = "ERR_DELETED"
	CodeRoleReserved       = "ERR_ROLE_RESERVED"
	CodeRoleInvalid        = "ERR_ROLE_INVALID"
	CodePasswordTooShort   = "ERR_PASSWORD_TOO_SHORT"
	CodePasswordTooLong    = "ERR_PASSWORD_TOO_LONG"
	Code2FARequired        = "ERR_2FA_REQUIRED"
	CodeCodeInvalid        = "ERR_CODE_INVALID"
	CodeCodeNotFound       = "ERR_CODE_NOT_FOUND"
	CodeRecipientMismatch  = "ERR_RECIPIENT_MISMATCH"
	CodeTooManyRequests    = "ERR_TOO_MANY_REQUESTS"
	CodeAccountLocked      = "ERR_ACCOUNT_LOCKED"
	CodeUnauthorized       = "ERR_UNAUTHORIZED"
	CodeForbidden          = "ERR_FORBIDDEN"
	CodeInternal           = "ERR_INTERNAL"
	CodeRegistrationToken  = "ERR_REGISTRATION_TOKEN"
	CodeInvalidCode        = "ERR_INVALID_CODE"
	CodeCodeExpired        = "ERR_CODE_EXPIRED"
	CodeWeakPassword       = "ERR_WEAK_PASSWORD"
)

// errResp returns a gin.H with error message and code
func errResp(code, message string) gin.H {
	return gin.H{"error": message, "code": code}
}
