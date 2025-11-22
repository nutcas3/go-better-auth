package util

func BuildVerificationURL(baseURL, basePath, token string, callbackURL *string) string {
	url := baseURL + basePath + "/verify-email?token=" + token
	if callbackURL != nil && *callbackURL != "" {
		url += "&callback_url=" + *callbackURL
	}
	return url
}
