# Tomatillo Design – Login Security

A lightweight WordPress security plugin focused on the basics:

* Enforces strong passwords (no weak-password bypass)
* Progressive throttling of login attempts
* Locks out abusive login behavior when necessary
* No settings pages, no custom tables, no external services

This plugin is intentionally simple, predictable, and easy to audit.

---

## What's New in v1.2

**Security improvements:**

* **Fixed lockout extension DoS vulnerability** — attackers can no longer indefinitely extend lockouts
* **Fixed global lockout message leak** — lockout messages are now scoped per-IP
* **Replaced hard 24h lockouts with progressive throttling** — reduces support friction on shared IPs and CDN environments

**Password policy modernization (NIST-aligned):**

* **Complexity rules now optional** (default OFF) — rigid uppercase/lowercase/number/special requirements disabled by default
* **Context-aware denylist screening** — rejects passwords containing username, email, site tokens, or common weak patterns
* **Improved error messages** — clearer, more specific feedback
* **Weak password checkbox removal now optional** (default OFF) — respects WordPress UI conventions

**Why progressive throttling?**

Hard 24-hour lockouts are hostile to legitimate users, especially on:

* Shared office/network IPs
* CDN/edge environments (WP Engine + Cloudflare, Rocket.net)
* Users who occasionally mistype passwords

Progressive throttling slows attackers to a crawl (2s → 5s → 15s → 60s delays) while allowing real users to recover quickly after the sliding window expires (default 15 minutes).

---

## What This Plugin Does

### Strong Password Enforcement

* Removes the "Confirm use of weak password" option from WordPress (optional in v1.2+)
* Enforces strong passwords server-side for:

  * User profile updates
  * Admin-created users
  * Password reset flow

Passwords must meet minimum length (default 12 chars) and pass context screening (no username/email/site tokens, no common weak passwords).

Rigid complexity requirements (uppercase/lowercase/number/special) are **optional** and disabled by default in v1.2+ (aligned with NIST guidance).

---

### Login Attempt Limiting

* **Progressive throttling** of repeated failed login attempts
* Temporarily blocks further attempts after a threshold is reached
* Emergency hard lock backstop for extreme abuse (default: 25 failures → 15 minute lock)
* Lockouts/throttles apply to abusive sources only (not globally)

This helps protect against:

* Brute-force attacks
* Password stuffing
* Automated credential testing

**Default throttle ladder:**

* 1-2 failures: no delay
* 3rd failure: 2 second delay
* 4th failure: 5 second delay
* 5th failure: 15 second delay
* 6+ failures: 60 second delay (cap)

Counts reset after 15 minutes of inactivity (sliding window).

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

### Login Throttling Examples

```php
// Adjust sliding window (default 15 minutes)
add_filter( 'tdls_login_window_seconds', function () {
    return 900;
});

// Customize progressive throttle ladder
add_filter( 'tdls_login_throttle_ladder', function () {
    return [
        1 => 0,
        2 => 0,
        3 => 5,   // 5s delay on 3rd failure
        4 => 15,
        5 => 30,
    ];
});

// Adjust emergency hard lock threshold
add_filter( 'tdls_login_hard_lock_threshold', function () {
    return 25; // lock after 25 failures in window
});
```

### Password Policy Examples

```php
// Increase minimum password length
add_filter( 'tdls_pw_min_length', function () {
    return 14;
});

// Enable rigid complexity requirements (uppercase/lowercase/number/special)
add_filter( 'tdls_pw_require_complexity', function () {
    return true; // default false in v1.2+
});

// Add custom weak passwords to denylist
add_filter( 'tdls_pw_weak_list', function ( $list ) {
    $list[] = 'companyname';
    $list[] = 'product123';
    return $list;
});

// Re-enable weak password checkbox removal (legacy behavior)
add_filter( 'tdls_remove_weak_checkbox', function () {
    return true; // default false in v1.2+
});
```

Additional filters exist for advanced use cases. See inline documentation in the plugin file.

---

## Proxy / CDN Environments

By default, the plugin identifies clients using the server-provided remote address.

If your site runs behind a trusted reverse proxy or CDN, you may need to override client IP detection.
This should only be done using headers provided by your hosting or CDN provider.

**Important:** v1.2's progressive throttling is much safer in CDN/edge environments than v1.0's hard lockouts, but you should still configure IP detection correctly if behind a proxy.

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
* Compatible with most hosting environments (tested on WP Engine, Rocket.net)
* Safe to use alongside 2FA and firewall plugins

---

## License

GPL-2.0-or-later

---

## Support

This plugin is maintained as part of the Tomatillo Design internal tooling ecosystem.

Review the source code to understand exact behavior.
Security-related behavior is intentionally explicit and easy to audit.
