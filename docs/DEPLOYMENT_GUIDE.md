# AMRSF Production Deployment Guide

## 1. Docker Compose Production Deployment (Recommended)

To deploy the full architecture (PostgreSQL database, Flask Backend API, and React Frontend Nginx container) on any production Linux or Windows server:

```bash
# 1. Clone Repository
git clone https://github.com/Sameer200510/AI-Based-Hybrid-Web-Application-Firewall.git
cd AI-Based-Hybrid-Web-Application-Firewall

# 2. Start all services via Docker Compose
docker-compose up --build -d
```

### Verified Endpoints:
- **Security Operations Center (SOC) Dashboard**: `http://localhost:80`
- **WAF Backend API**: `http://localhost:5000`
- **PostgreSQL Database**: Port `5432`

---

## 2. Nginx Reverse Proxy WAF Integration

To inspect traffic passing to your origin application server, integrate AMRSF as an auth/inspection proxy block inside `/etc/nginx/nginx.conf`:

```nginx
location / {
    # Send preflight inspection to AMRSF WAF API
    auth_request /_waf_inspect;
    proxy_pass http://origin_backend;
}

location = /_waf_inspect {
    internal;
    proxy_pass http://localhost:5000/api/v1/waf/inspect;
    proxy_pass_request_body on;
}
```
