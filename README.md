# Demeter
-----

<img width="600" height="816" alt="image" src="https://github.com/user-attachments/assets/1e7d269f-8419-4d01-9161-c7827900b2e2" /><br>
Demeter is a lightweight Flask-based tool designed to capture, store, and analyze incoming webhook requests. It provides a simple web interface for authenticated users to view webhook data, statistics, and manage request history. The application supports multiple HTTP methods, logs requests to a SQLite database, and includes features like session management, request caching, and periodic cleanup of old records.

## Features
- **Webhook Capture**: Handles GET, POST, PUT, DELETE, PATCH, and OPTIONS requests on any path.
- **Database Storage**: Stores webhook data (headers, payload, method, IP address, etc.) in a SQLite database.
- **User Authentication**: Secure login system with hashed passwords.
- **Dashboard**: Displays recent webhooks with details like timestamp, method, path, headers, and data.
- **Statistics API**: Provides insights into total requests, method distribution, and status counts.
- **Cache Management**: Maintains a memory cache of up to 50 recent webhooks for quick access.
- **Periodic Cleanup**: Automatically deletes webhook records older than 30 days.
- **Logging**: Logs application events and errors to a rotating log file.
- **Secure Session Management**: Uses a secure secret key for session handling.

## Prerequisites
- Python 3.6+
- Flask (`pip install flask`)
- SQLite3 (included with Python)
- No additional external services required

## Installation
**From Source**:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/webhook-catcher.git
   cd demeter
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python app.py
   ```
   The application will start on `http://0.0.0.0:13370`.

**From PyPI**:
1. PyPI Download:
   ```bash
   pip install demeter-tod
   ```
2. Run:
   ```bash
   demeter
   ```
   
## Usage
1. **Access the Application**:
   - Open your browser and navigate to `http://localhost:13370`.
   - Log in with the default credentials:
     - **Username**: `anonre`
     - **Password**: `hackerbiasa123`
2. **Webhook Endpoint**:
   - Send webhooks to any path (e.g., `http://localhost:13370`).
   - The application captures and stores the request details.
3. **Dashboard**:
   - View recent webhooks, including method, path, headers, data, and IP address.
   - Use the `/get-webhooks` endpoint to fetch webhook data via JavaScript.
4. **Statistics**:
   - Access the `/api/stats` endpoint to retrieve request statistics.
5. **Clear History**:
   - Use the `/clear` endpoint (POST) to clear the webhook history (requires authentication).
6. **Logout**:
   - Click the logout link to end the session.

## Configuration
- **Database**: The application uses a SQLite database (`webhooks.db`) to store webhook data and user credentials.
- **Logging**: Logs are stored in the `logs/` directory with a maximum size of 10MB per file and up to 5 backup files.
- **Cache**: The in-memory cache stores up to 50 recent webhooks for performance.
- **Cleanup**: Old records (>30 days) are automatically deleted daily.

## Project Structure
```
Demeter/
├── app.py              # Main Flask application
├── templates/          # HTML templates (index.html, login.html, 404.html)
├── logs/              # Log files (webhook.log)
├── webhooks.db        # SQLite database
└── requirements.txt    # Python dependencies
```

## Endpoints
- **GET /login**: Renders the login page.
- **POST /login**: Handles user login.
- **GET /logout**: Logs out the current user.
- **GET /dashboard**: Displays the webhook dashboard (requires authentication).
- **GET /get-webhooks**: Returns the cached webhook data as JSON.
- **POST /clear**: Clears the webhook history (requires authentication).
- **GET /api/stats**: Returns webhook statistics (requires authentication).
- **ANY /<path>**: Catches all webhook requests and stores them.

## Security
- **Password Hashing**: User passwords are hashed using SHA-256.
- **Session Management**: Secure session handling with a randomly generated secret key.
- **Input Validation**: Handles various input types (JSON, form data, query params) safely.
- **Error Handling**: Logs errors and returns meaningful responses.

## Logging
- Logs are stored in `logs/webhook.log` with rotation to prevent excessive disk usage.
- Example log entry:
  ```
  [2025-08-14 10:50:00] INFO in app: Webhook received: abc123 from 127.0.0.1 on path /test
  ```

## Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Create a Pull Request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact
For issues or suggestions, please open an issue on the [GitHub repository](https://github.com/yourusername/webhook-catcher).
