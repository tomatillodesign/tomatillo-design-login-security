=== Tomatillo Design – Login Security ===
Contributors: tomatillodesign
Tags: security, login, passwords, brute-force, hardening
Requires at least: 6.0
Tested up to: 6.9
Stable tag: 1.1.1
License: GPLv2 or later
License URI: [https://www.gnu.org/licenses/gpl-2.0.html](https://www.gnu.org/licenses/gpl-2.0.html)

A lightweight WordPress security plugin that enforces strong passwords and limits abusive login attempts.

== Description ==

Tomatillo Design – Login Security focuses on a few critical security controls and implements them cleanly:

* Enforces strong passwords (no weak-password bypass)
* Limits repeated failed login attempts
* Temporarily locks out abusive login behavior
* No settings pages, no custom database tables, no external services

The plugin is intentionally simple, predictable, and easy to audit. It is designed to reduce common attack vectors without introducing unnecessary complexity or user-facing configuration.

== Features ==

= Strong Password Enforcement =

* Removes the "Confirm use of weak password" option
* Enforces password strength server-side for:

  * User profile updates
  * Admin-created users
  * Password reset flow

Passwords must meet minimum length and complexity requirements.

= Login Attempt Limiting =

* Tracks repeated failed login attempts
* Temporarily blocks further attempts after a threshold is reached
* Lockouts apply to abusive sources only (not globally)

This helps protect against brute-force attacks, password stuffing, and automated credential testing.

== Design Philosophy ==

* No admin UI or dashboards
* No custom database tables
* No external APIs or services
* Server-side enforcement only
* Safe defaults that avoid accidental denial-of-service scenarios

Attackers who exceed limits lock themselves out; legitimate users are not affected by activity elsewhere.

== Configuration ==

This plugin does not include a settings page.

Behavior is configured via WordPress filters, which may be added in `functions.php`, a custom plugin, or a must-use plugin.

Example:

```
add_filter( 'tdls_login_max_attempts', function () {
    return 5;
});

add_filter( 'tdls_login_lockout_seconds', function () {
    return 24 * HOUR_IN_SECONDS;
});
```

Additional filters are available for advanced environments such as sites behind trusted proxies or CDNs.

== Proxy / CDN Environments ==

By default, client identification is based on the server-provided remote address.

If the site runs behind a trusted reverse proxy or CDN, client IP detection may need to be adjusted using the provided filters. Only trusted headers supplied by the hosting or CDN provider should be used.

== What This Plugin Does Not Do ==

* No global username lockouts
* No CAPTCHA or challenge-response UI
* No logging or analytics dashboards
* No protection against already-compromised credentials
* No replacement for hosting-level firewalls or two-factor authentication

This plugin is intended to be one layer in a broader security strategy.

== Installation ==

1. Upload the plugin to the `/wp-content/plugins/` directory
2. Activate the plugin through the WordPress Plugins screen
3. (Optional) Adjust behavior via filters if needed

== Compatibility ==

* WordPress 6.x and newer
* Compatible with standard login flows
* Safe to use alongside two-factor authentication and firewall plugins

== Changelog ==

= 1.0.0 =

* Initial release
* Strong password enforcement
* Removed weak password bypass
* Added simple login attempt limiting with temporary lockout
* Documented configuration filters

== License ==

This plugin is licensed under the GPLv2 or later.

== Support ==

This plugin is maintained as part of the Tomatillo Design internal tooling ecosystem.

Security-related behavior is intentionally explicit in code and designed to be easy to audit.
