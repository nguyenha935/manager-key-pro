# Manager Key Pro

SaaS-style downstream API key manager for [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).

## Features

- **User accounts**: username+password (argon2id) or Telegram Login
- **Wallet per user**: prepaid/postpaid, recharge via dashboard or Telegram webhook
- **Keys with quota**: credit/token/request × hour/day/week/month/lifetime
- **Billing**: cache-aware token pricing, hold/settle/release, anti-duplicate rules
- **Portal**: self-service register, buy packages, renew keys, check balance
- **Admin API**: full CRUD for users, keys, packages, pricing, audit
- **Affiliate**: multi-tier percent or fixed referral rewards

## Install

Add to your CPA `config.yaml`:

```yaml
plugins:
  store-sources:
    - "https://raw.githubusercontent.com/nguyenha935/cliproxy-plugins/main/registry.json"
```

Then install via Plugin Store UI, or download the release `.so` for your platform.

## Config

```yaml
plugins:
  configs:
    manager-key-pro:
      enabled: true
      priority: 5
      db_path: "manager-key-pro.db"
      encryption_key: "env:MKP_ENCRYPTION_KEY"  # 64 hex chars
      portal_listen: "127.0.0.1:8788"
      portal_base_url: "https://key.example.com"
      registration_open: true
```

## License

MIT
