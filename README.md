# Hook Collector

A simple but powerful Flask application for receiving, logging, and monitoring webhooks. Built for developers who need to debug and test webhook integrations.

## Features

- **Webhook Capture**: Receive and store webhooks from any source
- **Real-time Monitoring**: View incoming webhooks in real-time through the web interface
- **Authentication**: Secure access with username and password
- **Persistence**: All webhooks are stored in SQLite database
- **Rate Limiting**: Built-in protection against abuse
- **Search**: Filter webhooks by content
- **Statistics**: View usage statistics and metrics
- **Automatic Cleanup**: Webhooks older than 30 days are automatically removed

## Installation

### Prerequisites

- Python 3.6+
- pip

### Setup

1. Clone the repository:
```bash
git clone https://github.com/joelindra/HookCollector.git
cd HookCollector
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create requirements.txt with the following content:
```
flask
sqlite3
flask-limiter
```

4. Run the application:
```bash
python app.py
```

The application will be accessible at `http://localhost:5000`.

## Usage

### Login

Default login credentials:
- Username: `anonre`
- Password: `hackerbiasa123`

**Important:** Change these credentials immediately after first login by modifying the database.

### Receiving Webhooks

Send any HTTP request to the `/webhook` endpoint:

```bash
# Using curl
curl -X POST http://yourdomain.com/webhook -d '{"key": "value"}' -H "Content-Type: application/json"

# Or using any other HTTP client
```

The application accepts GET, POST, PUT, and DELETE methods and handles both JSON and form data.

### Web Interface

- **Dashboard**: View all received webhooks
- **Search**: Filter webhooks by content
- **Clear History**: Remove all stored webhooks
- **Stats**: View usage statistics

## Configuration

The application can be configured by editing the following variables in `app.py`:

- `MAX_CACHE_SIZE`: Maximum number of webhooks to keep in memory cache (default: 50)
- `app.secret_key`: Secret key for session management (auto-generated)
- Rate limiting: Configured to "200 per day, 50 per hour" by default

## Security Considerations

- This application is designed for development and testing purposes
- For production use, consider:
  - Using HTTPS
  - Implementing more robust authentication
  - Setting up proper database backups
  - Deploying behind a reverse proxy

## Directory Structure

```
webhook-collector/
├── app.py             # Main application file
├── webhooks.db        # SQLite database
├── requirements.txt   # Dependencies
├── logs/              # Log files
│   └── webhook.log    # Application logs
└── templates/         # HTML templates
    ├── index.html     # Dashboard template
    └── login.html     # Login template
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
