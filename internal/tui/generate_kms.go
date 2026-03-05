package tui

import (
	"github.com/charmbracelet/huh"
)

// YandexKMSAnswers holds the Yandex-specific KMS configuration from the wizard.
type YandexKMSAnswers struct {
	AuthMode string // "iam_token", "oauth_token", "metadata"
	IAMToken string
	KeyID    string
}

// runKMSWizard runs additional KMS prompts when the user selects a non-local provider.
// Returns nil answers if the provider is "local" (no extra config needed).
func runKMSWizard(provider string) (*YandexKMSAnswers, error) {
	if provider == "local" {
		return nil, nil
	}

	ans := &YandexKMSAnswers{
		AuthMode: "iam_token",
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("  Yandex Cloud KMS Configuration").
				Description("Configure authentication for Yandex Cloud KMS.\n"+
					"The IAM token is required to encrypt/decrypt secrets."),

			huh.NewSelect[string]().
				Title("Authentication mode").
				Description("How to authenticate with Yandex Cloud KMS").
				Options(
					huh.NewOption("IAM Token — static token for easy dev/testing (recommended)", "iam_token"),
					huh.NewOption("OAuth Token — exchanged for IAM tokens automatically", "oauth_token"),
					huh.NewOption("Metadata — use VM metadata service (inside Yandex Cloud)", "metadata"),
				).
				Value(&ans.AuthMode),
		),

		// IAM token input — shown only for iam_token mode
		huh.NewGroup(
			huh.NewInput().
				Title("IAM token value").
				Description("Paste your Yandex Cloud IAM token.\n"+
					"You can generate one with: yc iam create-token").
				Value(&ans.IAMToken).
				Placeholder("t1.9euelZq..."),
		).WithHideFunc(func() bool { return ans.AuthMode != "iam_token" }),

		// KMS Key ID
		huh.NewGroup(
			huh.NewInput().
				Title("KMS Key ID").
				Description("The Yandex Cloud KMS symmetric key ID used for encryption").
				Value(&ans.KeyID).
				Placeholder("abjxxxxxxxxxxxxxxxx"),
		),
	).WithTheme(huh.ThemeCatppuccin())

	if err := form.Run(); err != nil {
		return nil, err
	}

	return ans, nil
}
