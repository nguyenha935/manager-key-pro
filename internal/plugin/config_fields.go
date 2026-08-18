package plugin

// registrationMetadata returns the metadata block for plugin.register.
// ConfigFields drives the panel's visual config editor.
func registrationMetadata() map[string]any {
	return map[string]any{
		"Name":             "Manager Key Pro",
		"Version":          "0.1.0",
		"Author":           "nguyenha935",
		"GitHubRepository": "https://github.com/nguyenha935/manager-key-pro",
		"ConfigFields": []map[string]any{
			{
				"Name":        "enabled",
				"Type":        "boolean",
				"Description": "Bật/tắt plugin Manager Key Pro.",
			},
			{
				"Name":        "priority",
				"Type":        "integer",
				"Description": "Thứ tự ưu tiên auth. Số nhỏ hơn = chạy trước.",
			},
			{
				"Name":        "db_path",
				"Type":        "string",
				"Description": "Đường dẫn file SQLite. Mặc định: manager-key-pro.db trong thư mục CPA.",
			},
			{
				"Name":        "encryption_key",
				"Type":        "string",
				"Description": "Khóa AES-256 để reveal key. 64 ký tự hex, hoặc env:TÊN_BIẾN. BẮT BUỘC đặt trước khi dùng thật.",
			},
			{
				"Name":        "log_mode",
				"Type":        "enum",
				"EnumValues":  []string{"standard", "full", "error_only"},
				"Description": "Chế độ log. standard = mặc định, full = ghi context debug, error_only = chỉ log lỗi.",
			},
			{
				"Name":        "portal_listen",
				"Type":        "string",
				"Description": "Địa chỉ listener cho portal người dùng. VD: 127.0.0.1:8788. Để trống = tắt portal.",
			},
			{
				"Name":        "portal_base_url",
				"Type":        "string",
				"Description": "URL công khai của portal (để tạo link giới thiệu). VD: https://key.example.com.",
			},
			{
				"Name":        "registration_open",
				"Type":        "boolean",
				"Description": "Cho phép người dùng tự đăng ký qua portal. Tắt = chỉ admin tạo được user.",
			},
			{
				"Name":        "require_approval",
				"Type":        "boolean",
				"Description": "User mới đăng ký phải chờ admin duyệt trước khi dùng được.",
			},
			{
				"Name":        "min_password_len",
				"Type":        "integer",
				"Description": "Độ dài tối thiểu của mật khẩu khi đăng ký. Mặc định 8.",
			},
			{
				"Name":        "login_lock_after",
				"Type":        "integer",
				"Description": "Số lần đăng nhập sai liên tiếp trước khi khóa tài khoản. Mặc định 5.",
			},
			{
				"Name":        "session_ttl_days",
				"Type":        "integer",
				"Description": "Số ngày session người dùng còn hiệu lực. Mặc định 14.",
			},
			{
				"Name":        "telegram_bot_token",
				"Type":        "string",
				"Description": "Bot token Telegram Login Widget + webhook nạp ví. Để trống = tắt Telegram.",
			},
			{
				"Name":        "telegram_webhook_secret",
				"Type":        "string",
				"Description": "Secret chung cho webhook nạp ví Telegram (header X-Webhook-Secret).",
			},
		},
	}
}
