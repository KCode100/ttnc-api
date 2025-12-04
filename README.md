# TTNC Call Forwarding API

A secure API wrapper for TTNC's call forwarding service. Allows programmatic control of destination numbers via a simple REST endpoint.

## Features

- **Simple REST API** - Single endpoint to set call forwarding destination
- **Automatic session management** - Handles TTNC authentication and session caching
- **Production-ready** - Rate limiting, security headers, structured logging
- **API key authentication** - Secure access control

## Quick Start

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment

```bash
cp env.example .env
```

Edit `.env` with your TTNC credentials:

```
TTNC_USERNAME=your_username
TTNC_PASSWORD=your_password
TTNC_VKEY=your_vkey
TTNC_NUMBER=your_ttnc_number
API_KEY=your-secret-api-key-min-32-chars
```

### 3. Run the server

```bash
npm start
```

## API Endpoints

### Health Check

```
GET /health
```

Returns server status. No authentication required.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2024-12-04T10:30:00.000Z",
  "version": "1.0.0"
}
```

### Set Destination

```
POST /set-destination
```

Updates the call forwarding destination for your TTNC number.

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | `application/json` |
| `X-API-Key` | Yes | Your API key |

**Body:**
```json
{
  "destination": "447573683626"
}
```

> **Note:** Use international format without leading `00` or `+` (e.g., `447573683626` for UK mobile)

**Success Response:**
```json
{
  "success": true,
  "message": "Destination Set Successfully"
}
```

**Error Response:**
```json
{
  "error": "Invalid destination format. Use country code + number (e.g., 447573683626)"
}
```

### Example Request

```bash
curl -X POST https://your-api.com/set-destination \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"destination": "447573683626"}'
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TTNC_USERNAME` | Yes | TTNC account username |
| `TTNC_PASSWORD` | Yes | TTNC account password |
| `TTNC_VKEY` | Yes | TTNC application VKey |
| `TTNC_NUMBER` | Yes | Your TTNC number to configure |
| `API_KEY` | Yes | API key for authentication (min 32 chars) |
| `PORT` | No | Server port (default: 3000) |
| `CORS_ORIGIN` | No | Allowed CORS origin (default: *) |

## Deployment

### Railway (Recommended)

1. Push to GitHub
2. Connect repo at [railway.app](https://railway.app)
3. Add environment variables in Railway dashboard
4. Get static IP from Railway → Settings → Networking
5. Add static IP to your TTNC VKey settings

### Important: IP Whitelisting

TTNC requires IP whitelisting for API access. Your hosting must have a **static outbound IP** that you add to your TTNC VKey configuration.

## Security Features

- **Helmet** - Secure HTTP headers
- **Rate limiting** - 30 requests/minute per IP
- **Timing-safe comparison** - Prevents API key timing attacks
- **Input validation** - Strict destination format validation
- **XML escaping** - Prevents injection attacks
- **Premium number blocking** - Blocks UK 09xx numbers

## Integration Example (Next.js)

```javascript
// pages/api/set-destination.js
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const response = await fetch(`${process.env.TTNC_API_URL}/set-destination`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': process.env.TTNC_API_KEY
    },
    body: JSON.stringify({ destination: req.body.destination })
  });

  const data = await response.json();
  res.status(response.ok ? 200 : 500).json(data);
}
```

## License

Private - Internal use only

