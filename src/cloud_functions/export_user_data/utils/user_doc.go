package utils

type profileInfo struct {
	ImageUrl string `json:"profile_image"`
	BannerUrl string `json:"banner_image,omitempty"`
	Bio string `json:"bio,omitempty"`
	Location string `json:"location,omitempty"`
	Url string `json:"website,omitempty"`
}

type socialInfo struct {
	Followers int `json:"followers"`
	Following int `json:"following"`
	Pending int `json:"pending"`
	Requests int `json:"requests"`
}

type profilePrivacy struct {
	ProfileLocation string `json:"profile_location"`
	ProfileUrl string `json:"profile_url"`
}

type privacyInfo struct {
	SendDMs string `json:"send_direct_messages"`
	BeFollowers string `json:"followers_settings"`
	SeePosts string `json:"posts_privacy"`
	SearchIndexed string `json:"search_visibility"`
	Profile profilePrivacy `json:"profile_privacy"`
	LastUpdated int64 `json:"last_updated"`
}

type lastAccessedInfo struct {
	Location string `json:"location"`
	Date int64 `json:"date"`
}

type securityInfo struct {
	LastAccessed []lastAccessedInfo `json:"last_accessed,omitempty"`
	HasAuth2FA bool `json:"has_authenticator_2fa,omitempty"`
	HasSMS2FA bool `json:"has_sms_2fa,omitempty"`
	BackupCode string `json:"backup_code,omitempty"`
}

type sessionInfo struct {
	SessionId string `json:"session_id"`
	AddedOn int64 `json:"created_at"`
	ExpiryDate int64 `json:"expires_at"`
	IpAddress string `json:"ip_address"`
	Browser string `json:"browser"`
	Os string `json:"os"`
	Location string `json:"location"`
	UserAgent string `json:"user_agent"`
}

type formattedUserDoc struct {
	Id string `json:"id"`
	Profile profileInfo `json:"profile"`
	Username string `json:"username"`
	DisplayName string `json:"display_name"`
	Email string `json:"email"`
	MiraiPlus bool `json:"mirai_plus"`
	ContentModeration map[string]bool `json:"content_moderation"`
	Oauth []string `json:"linked_accounts,omitempty"`
	Social socialInfo `json:"social"`
	Privacy privacyInfo `json:"privacy"`
	Security securityInfo `json:"security"`
	PhoneNum string `json:"phone_number,omitempty"`
	CreatedAt int64 `json:"joined_at"`
	Sessions []sessionInfo `json:"sessions,omitempty"`
}