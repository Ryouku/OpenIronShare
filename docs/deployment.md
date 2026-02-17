# Deployment Guide

## Overview

IronShare compiles to a single binary. Two deployment options are supported: **Docker** (recommended) and **systemd** (bare metal).

## Prerequisites

- Linux server (Ubuntu 22.04+ recommended)
- Reverse proxy (Nginx or Caddy) for TLS termination
- Valid SSL certificate (Let's Encrypt recommended)
- Domain name

## Option 1: Docker (Recommended)

The repository includes a production-ready `Dockerfile` and `docker-compose.yml`.

### Quick Start

```bash
git clone https://github.com/Ryouku/OpenIronShare.git
cd OpenIronShare

# Start with Docker Compose
docker compose up -d
```

API available at `http://localhost:3000`.

### Configuration

Override defaults via environment variables in `docker-compose.yml`:

```yaml
environment:
  - DATABASE_URL=sqlite:/data/ironshare.db
  - IRONSHARE_HOST=0.0.0.0
  - IRONSHARE_PORT=3000
  - RUST_LOG=info
```

### Data Persistence

The named volume `ironshare-data` persists the SQLite database at `/data/ironshare.db`.

```bash
# Inspect volume location
docker volume inspect ironshare_ironshare-data

# Backup database
docker exec ironshare sqlite3 /data/ironshare.db ".backup /data/backup.db"
docker cp ironshare:/data/backup.db ./backup-$(date +%Y%m%d).db
```

### Updates

```bash
docker compose pull
docker compose up -d
```

---

## Option 2: Systemd (Bare Metal)

### 1. Build

```bash
git clone https://github.com/Ryouku/OpenIronShare.git
cd OpenIronShare

cargo build --release
# Binary: ./target/release/ironshare
```

For cross-compilation:

```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-musl
```

### 2. Install

```bash
# Create system user
sudo useradd -r -s /bin/false ironshare

# Create directories
sudo mkdir -p /opt/ironshare
sudo mkdir -p /var/lib/ironshare

# Copy binary
sudo cp target/release/ironshare /opt/ironshare/
sudo chown -R ironshare:ironshare /opt/ironshare /var/lib/ironshare
sudo chmod 755 /opt/ironshare/ironshare
```

### 3. Configure

```bash
sudo nano /etc/ironshare.env
```

```bash
DATABASE_URL=sqlite:/var/lib/ironshare/ironshare.db
IRONSHARE_HOST=127.0.0.1
IRONSHARE_PORT=3000
RUST_LOG=info
```

```bash
sudo chown ironshare:ironshare /etc/ironshare.env
sudo chmod 600 /etc/ironshare.env
```

### 4. Systemd Service

The `deploy/ironshare.service` file in the repository is ready to use:

```bash
sudo cp deploy/ironshare.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ironshare
sudo systemctl start ironshare
sudo systemctl status ironshare
```

Or create manually (`/etc/systemd/system/ironshare.service`):

```ini
[Unit]
Description=IronShare - Zero-Knowledge Secret Sharing API
After=network.target

[Service]
Type=simple
User=ironshare
Group=ironshare
WorkingDirectory=/opt/ironshare
EnvironmentFile=/etc/ironshare.env
ExecStart=/opt/ironshare/ironshare
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ironshare

# Resource limits
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

---

## Reverse Proxy Configuration

### Nginx

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

`/etc/nginx/sites-available/ironshare`:

```nginx
upstream ironshare {
    server 127.0.0.1:3000;
}

server {
    listen 80;
    server_name YOUR_DOMAIN;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name YOUR_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Content-Security-Policy "default-src 'none'; script-src 'self'; connect-src 'self'" always;

    access_log /var/log/nginx/ironshare-access.log;
    error_log /var/log/nginx/ironshare-error.log;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;

    location /api/ {
        limit_req zone=api burst=5 nodelay;
        proxy_pass http://ironshare;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://ironshare;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/ironshare /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

Get certificate:

```bash
sudo certbot --nginx -d YOUR_DOMAIN
```

### Caddy (Automatic TLS)

`/etc/caddy/Caddyfile`:

```caddy
YOUR_DOMAIN {
    reverse_proxy 127.0.0.1:3000

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        Content-Security-Policy "default-src 'none'; script-src 'self'; connect-src 'self'"
    }

    log {
        output file /var/log/caddy/ironshare-access.log
    }
}
```

```bash
sudo systemctl reload caddy
```

---

## Firewall

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 3000/tcp
sudo ufw enable
```

---

## Database Backup

```bash
# Manual backup
sqlite3 /var/lib/ironshare/ironshare.db ".backup '/var/backups/ironshare-$(date +%Y%m%d).db'"

# Cron (daily at 2 AM, 7-day retention)
sudo crontab -u ironshare -e
```

```cron
0 2 * * * sqlite3 /var/lib/ironshare/ironshare.db ".backup '/var/backups/ironshare-$(date +\%Y\%m\%d).db'" && find /var/backups -name "ironshare-*.db" -mtime +7 -delete
```

---

## Monitoring

```bash
# Service status
sudo systemctl status ironshare
sudo journalctl -u ironshare -f

# Health check
curl http://127.0.0.1:3000/health

# Database size
du -h /var/lib/ironshare/ironshare.db
```

---

## Updates (Systemd)

```bash
sudo systemctl stop ironshare
sudo cp target/release/ironshare /opt/ironshare/
sudo chown ironshare:ironshare /opt/ironshare/ironshare
sudo systemctl start ironshare
sudo systemctl status ironshare
```

---

## Troubleshooting

### Service won't start

```bash
sudo journalctl -u ironshare -n 50
ls -la /var/lib/ironshare
sudo -u ironshare /opt/ironshare/ironshare
```

### Database locked

```bash
lsof /var/lib/ironshare/ironshare.db
sudo systemctl restart ironshare
```

---

## Production Checklist

- [ ] HTTPS enabled with valid certificate
- [ ] Security headers configured in reverse proxy
- [ ] Rate limiting enabled
- [ ] Firewall rules applied (port 3000 blocked externally)
- [ ] Automated database backups configured
- [ ] Health check endpoint reachable (`GET /health`)
- [ ] Service auto-starts on boot (`systemctl enable`)
- [ ] `RUST_LOG=info` (not `debug`) in production
- [ ] Test store and retrieve via API
- [ ] Test burn-after-reading (`max_views: 1`)
- [ ] Test expiration (`ttl_minutes`)
