# Tomatillo Design – Login Security

A lightweight WordPress security plugin focused on the basics:

* Enforces strong passwords (no weak-password bypass)
* Limits login attempts
* Locks out abusive login behavior for a fixed period
* No settings pages, no custom tables, no external services

This plugin is intentionally simple, predictable, and easy to audit.

---

## What This Plugin Does

### Strong Password Enforcement

* Removes the “Confirm use of weak password” option from WordPress
* Enforces strong passwords server-side for:

  * User profile updates
  * Admin-created users
  * Password reset flow

Passwords must meet minimum length and complexity requirements.

---

### Login Attempt Limiting

* Limits repeated failed login attempts
* Temporarily blocks further attempts after a threshold is reached
* Lockouts apply to abusive sources only (not globally)

This helps protect against:

* Brute-force attacks
* Password stuffing
* Automated credential testing

---

## Design Philosophy

* **No UI**: No dashboards, logs, or settings screens
* **No custom tables**: Uses WordPress transients only
* **No external dependencies**
* **Server-side enforcement** (not JavaScript tricks)
* **Safe defaults** that avoid accidental denial-of-service scenarios

Attackers who exceed limits lock *themselves* out — legitimate users are not penalized by activity elsewhere.

---

## Configuration

This plugin has **no settings page**.

All behavior is configurable via WordPress filters.
Filters may be placed in `functions.php`, a custom plugin, or a must-use plugin.

Examples:

```php
// Change the number of allowed failed login attempts
add_filter( 'tdls_login_max_attempts', function () {
    return 5;
});

// Change lockout duration (in seconds)
add_filter( 'tdls_login_lockout_seconds', function () {
    return 24 * HOUR_IN_SECONDS;
});
```

Additional filters exist for advanced use cases such as proxy environments.

---

## Proxy / CDN Environments

By default, the plugin identifies clients using the server-provided remote address.

If your site runs behind a trusted reverse proxy or CDN, you may need to override client IP detection.
This should only be done using headers provided by your hosting or CDN provider.

(Consult your infrastructure documentation before overriding IP detection.)

---

## What This Plugin Does *Not* Do

* No global username lockouts
* No CAPTCHA or challenge-response UI
* No logging or analytics dashboards
* No protection against compromised credentials already in use
* No replacement for hosting-level firewalls or 2FA

This plugin is intended to be one layer in a broader security strategy.

---

## Compatibility

* WordPress 6.x+
* Works with standard login flows
* Compatible with most hosting environments
* Safe to use alongside 2FA and firewall plugins

---

## License

GPL-2.0-or-later

---

## Support

This plugin is maintained as part of the Tomatillo Design internal tooling ecosystem.

Review the source code to understand exact behavior.
Security-related behavior is intentionally explicit and easy to audit.
