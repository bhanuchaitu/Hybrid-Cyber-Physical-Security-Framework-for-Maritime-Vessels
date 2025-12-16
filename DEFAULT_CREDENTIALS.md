# Default Login Credentials

## Test Accounts

These are the default test credentials created automatically when the application starts for the first time.

### Available Accounts

| Username | Password | Role | Email |
|----------|----------|------|-------|
| `admin` | `admin123` | Administrator | admin@maritime-ids.local |
| `captain` | `captain123` | Captain | captain@maritime-ids.local |
| `security` | `security123` | Security Officer | security@maritime-ids.local |
| `demo` | `demo123` | Demo User | demo@maritime-ids.local |

## Quick Login

1. Navigate to: `http://localhost:5000/`
2. Click "Get Started" or go to the sign-in page
3. Enter username and password from the table above
4. Click "Sign In"

## Security Warning ⚠️

**IMPORTANT**: These are DEFAULT TEST CREDENTIALS for development and demonstration purposes only.

### For Production Deployment:

1. **IMMEDIATELY CHANGE ALL DEFAULT PASSWORDS**
2. Use strong passwords (12+ characters, mixed case, numbers, symbols)
3. Implement password expiration policies
4. Enable two-factor authentication (2FA)
5. Use environment variables for sensitive data
6. Consider OAuth2/LDAP/Active Directory integration
7. Implement account lockout after failed login attempts
8. Use HTTPS/TLS encryption for all traffic
9. Regular security audits and penetration testing
10. Monitor and log all authentication attempts

## Password Change

To change passwords manually:

### Option 1: Using Python (Development)
```python
import sqlite3
from werkzeug.security import generate_password_hash

# Connect to database
conn = sqlite3.connect('data/users.db')
cursor = conn.cursor()

# Update password
new_password = generate_password_hash('your-new-secure-password')
cursor.execute("UPDATE info SET password = ? WHERE user = ?", (new_password, 'admin'))

conn.commit()
conn.close()
```

### Option 2: Via Web UI
(If implemented) Navigate to Profile Settings → Change Password

### Option 3: Remove Default Users
```python
import sqlite3

conn = sqlite3.connect('data/users.db')
cursor = conn.cursor()

# Remove specific user
cursor.execute("DELETE FROM info WHERE user = ?", ('demo',))

# Or remove all users and start fresh
cursor.execute("DELETE FROM info")

conn.commit()
conn.close()
```

## Account Roles & Permissions

### Administrator (`admin`)
- Full system access
- Can modify all configurations
- Access to all monitoring dashboards
- User management capabilities (if implemented)
- System configuration changes

### Captain (`captain`)
- Maritime operations monitoring
- View vessel positions and trajectories
- Access to maritime dashboard
- View alerts and notifications
- Generate reports

### Security Officer (`security`)
- Security monitoring and alerts
- View intrusion detection results
- Access to cyber monitoring dashboard
- Alert management
- Incident response

### Demo User (`demo`)
- Read-only access
- Limited to viewing dashboards
- Cannot modify configurations
- Cannot delete or modify data
- Ideal for demonstrations

## Troubleshooting

### Cannot Login?

1. **Check if database exists**: `data/users.db` should be created automatically
2. **Verify virtual environment is activated**: `.venv\Scripts\activate`
3. **Check application is running**: Should see "Running on http://localhost:5000"
4. **Clear browser cache**: Sometimes cached login state causes issues
5. **Check logs**: `logs/flask_app.log` for authentication errors

### "Invalid credentials" error?

1. **Case sensitivity**: Usernames and passwords are case-sensitive
2. **Trailing spaces**: Make sure no spaces before/after username/password
3. **Database initialization**: Check if default users were created (see logs)
4. **Password hash issue**: Verify Werkzeug is installed correctly

### Forgot custom password?

If you changed a password and forgot it, you can:
1. Delete the database file: `data/users.db`
2. Restart the application (will recreate with default passwords)
3. Or use the Python script above to reset specific user password

## Compliance Notes

### GDPR / Data Privacy
- User credentials stored in SQLite database
- Passwords hashed using pbkdf2:sha256
- No plaintext password storage
- Email addresses used only for notifications
- Right to erasure: Delete user records as needed

### Industry Standards
- Follows OWASP authentication guidelines
- Password hashing meets NIST recommendations
- Session management via Flask sessions
- CSRF protection enabled

### Audit Trail
All authentication attempts are logged to:
- `logs/flask_app.log` - Application logs
- Database: Consider adding `login_attempts` table for production

## Support

For issues with login or credentials:
1. Check the comprehensive README.md
2. Review logs in `logs/` directory
3. Verify database initialization in console output
4. Create GitHub issue with details

---

**Last Updated**: December 16, 2025
**Project**: Hybrid Cyber-Physical Security Framework for Maritime Vessels
**Version**: 1.0.0
