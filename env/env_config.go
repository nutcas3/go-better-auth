package env

const (
	// OAUTH2 PROVIDERS

	EnvGoogleClientID     = "GOOGLE_CLIENT_ID"
	EnvGoogleClientSecret = "GOOGLE_CLIENT_SECRET"

	EnvDiscordClientID     = "DISCORD_CLIENT_ID"
	EnvDiscordClientSecret = "DISCORD_CLIENT_SECRET"

	EnvGithubClientID     = "GITHUB_CLIENT_ID"
	EnvGithubClientSecret = "GITHUB_CLIENT_SECRET"

	// GO BETTER AUTH

	EnvConfigPath  = "GO_BETTER_AUTH_CONFIG_PATH"
	EnvAdminApiKey = "GO_BETTER_AUTH_ADMIN_API_KEY"
	EnvSecret      = "GO_BETTER_AUTH_SECRET"
	EnvDatabaseURL = "GO_BETTER_AUTH_DATABASE_URL"
	EnvBaseURL     = "GO_BETTER_AUTH_BASE_URL"

	// ENVIRONMENT

	EnvGoEnvironment = "GO_ENV"
	EnvPort          = "PORT"
)
