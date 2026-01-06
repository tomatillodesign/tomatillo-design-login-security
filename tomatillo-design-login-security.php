<?php
/**
 * Plugin Name: Tomatillo Design – Login Security
 * Description: Enforces strong WordPress passwords, removes weak password bypass, and limits login attempts (simple lockout).
 * Version: 1.2.0
 * Author: Tomatillo Design
 * License: GPL-2.0+
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * ============================================================
 * Tomatillo Design – Login Security
 * ============================================================
 *
 * CONFIG VIA FILTERS (no settings page)
 *
 * Put these in functions.php or a mu-plugin:
 *
 * === LOGIN ATTEMPT LIMITING ===
 *
 * add_filter( 'tdls_login_max_attempts', function() {
 *     return 5; // default 5 (legacy; now mostly replaced by progressive throttling)
 * });
 *
 * add_filter( 'tdls_login_window_seconds', function() {
 *     return 900; // default 900 (15 minutes) - sliding window for count reset
 * });
 *
 * add_filter( 'tdls_login_throttle_ladder', function() {
 *     // Progressive delay ladder (count => seconds)
 *     return [
 *         1 => 0,
 *         2 => 0,
 *         3 => 2,
 *         4 => 5,
 *         5 => 15,
 *     ];
 * });
 *
 * add_filter( 'tdls_login_throttle_default_cap', function() {
 *     return 60; // default 60s cap for counts beyond ladder
 * });
 *
 * add_filter( 'tdls_login_hard_lock_threshold', function() {
 *     return 25; // default 25 - emergency hard lock backstop
 * });
 *
 * add_filter( 'tdls_login_hard_lock_duration', function() {
 *     return 15 * MINUTE_IN_SECONDS; // default 15 minutes
 * });
 *
 * add_filter( 'tdls_login_use_ip_key', function() {
 *     return true; // default true (throttles/locks an IP after too many failures)
 * });
 *
 * add_filter( 'tdls_login_use_combined_key', function() {
 *     return true; // default true (throttles/locks IP+username combo too)
 * });
 *
 * add_filter( 'tdls_login_transient_prefix', function() {
 *     return 'tdls_ll_'; // default 'tdls_ll_'
 * });
 *
 * === PASSWORD POLICY ===
 *
 * add_filter( 'tdls_pw_min_length', function() {
 *     return 12; // default 12
 * });
 *
 * add_filter( 'tdls_pw_require_complexity', function() {
 *     return false; // default false (v1.2+) - uppercase/lowercase/number/special enforcement
 * });
 *
 * add_filter( 'tdls_pw_check_username', function() {
 *     return true; // default true - reject passwords containing username/display name
 * });
 *
 * add_filter( 'tdls_pw_check_email', function() {
 *     return true; // default true - reject passwords containing email local-part
 * });
 *
 * add_filter( 'tdls_pw_check_site_tokens', function() {
 *     return true; // default true - reject passwords containing site domain/name
 * });
 *
 * add_filter( 'tdls_pw_weak_list', function() {
 *     return [ 'password', '123456', 'qwerty', /* ... */ ];
 * });
 *
 * add_filter( 'tdls_remove_weak_checkbox', function() {
 *     return false; // default false (v1.2+) - remove WordPress weak password checkbox UI
 * });
 *
 * === CLIENT IP DETECTION ===
 *
 * IMPORTANT (reverse proxy/CDN):
 * By default we use $_SERVER['REMOTE_ADDR'].
 * If your site is behind Cloudflare / a reverse proxy, you may need to override IP detection
 * using a trusted header appropriate for your environment:
 *
 * add_filter( 'tdls_login_client_ip', function( $ip ) {
 *     // Example ONLY — do not blindly trust arbitrary headers.
 *     // return isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? $_SERVER['HTTP_CF_CONNECTING_IP'] : $ip;
 *     return $ip;
 * });
 *
 * NOTE:
 * This plugin does NOT implement global username lockouts (to avoid easy DoS).
 * Lockouts and throttles are per-IP and per-IP+username by default.
 *
 * v1.2 replaced hard 24h lockouts with progressive throttling for better UX and
 * reduced support friction on shared IPs and CDN environments.
 */

final class Tomatillo_Design_Login_Security {

	const VERSION = '1.2.0';

	public static function init(): void {

		/**
		 * =========================
		 * Strong password behavior
		 * =========================
		 */
		add_action( 'admin_enqueue_scripts', [ __CLASS__, 'admin_remove_weak_pw_checkbox' ] );
		add_action( 'user_profile_update_errors', [ __CLASS__, 'enforce_strong_password_on_profile_save' ], 10, 3 );
		add_filter( 'validate_password_reset', [ __CLASS__, 'enforce_strong_password_on_reset' ], 10, 2 );

		/**
		 * =========================
		 * Login attempt limiting
		 * =========================
		 */
		add_filter( 'authenticate', [ __CLASS__, 'maybe_block_locked_out_login' ], 15, 3 );
		add_action( 'wp_login_failed', [ __CLASS__, 'record_failed_login' ], 10, 1 );
		add_action( 'wp_login', [ __CLASS__, 'clear_attempts_on_success' ], 10, 2 );
		add_filter( 'login_errors', [ __CLASS__, 'maybe_customize_login_error' ] );
	}

	/* ============================================================
	 * Strong passwords
	 * ============================================================
	 */

	public static function admin_remove_weak_pw_checkbox(): void {

		// Optional: remove weak password checkbox (default OFF in v1.2).
		$remove_checkbox = (bool) apply_filters( 'tdls_remove_weak_checkbox', false );
		if ( ! $remove_checkbox ) {
			return;
		}

		// Only runs where WP has enqueued this script (user/profile screens).
		wp_add_inline_script(
			'password-strength-meter',
			"jQuery(function($){
				function tdlsRemoveWeak(){ $('.pw-weak').remove(); }
				tdlsRemoveWeak();
				$(document).on('ajaxComplete', tdlsRemoveWeak);
			});"
		);
	}

	/**
	 * WP sometimes passes a lightweight stdClass user object into this hook.
	 * Do NOT typehint WP_User here; normalize safely.
	 */
	public static function enforce_strong_password_on_profile_save( WP_Error $errors, bool $update, $user ): void {

		// Normalize $user (WP_User or stdClass with ->ID).
		if ( $user instanceof WP_User ) {
			// ok
		} elseif ( is_object( $user ) && isset( $user->ID ) ) {
			$user = get_user_by( 'id', (int) $user->ID );
		}

		if ( ! ( $user instanceof WP_User ) ) {
			return;
		}

		// Only validate when a password is being set/changed.
		$pass1 = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
		if ( '' === $pass1 ) {
			return;
		}

		// If pass2 exists, ensure matching.
		$pass2 = isset( $_POST['pass2'] ) ? (string) $_POST['pass2'] : '';
		if ( '' !== $pass2 && $pass1 !== $pass2 ) {
			$errors->add( 'tdls_password_mismatch', __( 'Passwords do not match.', 'tomatillo-design-login-security' ) );
			return;
		}

		self::validate_password_or_add_errors( $pass1, $errors, $user );
	}

	public static function enforce_strong_password_on_reset( WP_Error $errors, WP_User $user ): WP_Error {

		$pass1 = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
		if ( '' === $pass1 ) {
			return $errors;
		}

		self::validate_password_or_add_errors( $pass1, $errors, $user );
		return $errors;
	}

	/**
	 * Password rules:
	 * - Minimum length (default 12; filterable via tdls_pw_min_length)
	 * - Optional complexity requirement (uppercase, lowercase, number, special)
	 * - Context denylist screening (username, email, common weak passwords)
	 * - No leading/trailing whitespace
	 */
	private static function validate_password_or_add_errors( string $password, WP_Error $errors, $user = null ): void {

		$password = (string) $password;

		// Minimum length check.
		$min_length = (int) apply_filters( 'tdls_pw_min_length', 12 );
		if ( strlen( $password ) < $min_length ) {
			$errors->add(
				'tdls_pw_length',
				sprintf(
					__( 'Password must be at least %d characters long.', 'tomatillo-design-login-security' ),
					$min_length
				)
			);
		}

		// Optional complexity requirement (default OFF in v1.2).
		$require_complexity = (bool) apply_filters( 'tdls_pw_require_complexity', false );
		if ( $require_complexity ) {
			$has_upper   = (bool) preg_match( '/[A-Z]/', $password );
			$has_lower   = (bool) preg_match( '/[a-z]/', $password );
			$has_number  = (bool) preg_match( '/[0-9]/', $password );
			$has_special = (bool) preg_match( '/[^a-zA-Z0-9]/', $password );

			if ( ! $has_upper || ! $has_lower || ! $has_number || ! $has_special ) {
				$errors->add(
					'tdls_pw_complexity',
					__( 'Password must include uppercase, lowercase, numbers, and special characters.', 'tomatillo-design-login-security' )
				);
			}
		}

		// Whitespace check.
		if ( $password !== trim( $password ) ) {
			$errors->add(
				'tdls_pw_whitespace',
				__( 'Password cannot begin or end with whitespace.', 'tomatillo-design-login-security' )
			);
		}

		// Context denylist screening.
		self::check_password_denylist( $password, $errors, $user );
	}

	/**
	 * Check password against context-aware denylist.
	 * Screens for username, email, site tokens, and common weak passwords.
	 */
	private static function check_password_denylist( string $password, WP_Error $errors, $user ): void {

		$password_lower = strtolower( $password );

		// Build list of forbidden tokens.
		$forbidden_tokens = [];

		// Username and display name tokens.
		$check_username = (bool) apply_filters( 'tdls_pw_check_username', true );
		if ( $check_username && $user instanceof WP_User ) {
			if ( ! empty( $user->user_login ) ) {
				$forbidden_tokens[] = strtolower( $user->user_login );
			}
			if ( ! empty( $user->display_name ) ) {
				$forbidden_tokens[] = strtolower( $user->display_name );
			}
		}

		// Email local-part.
		$check_email = (bool) apply_filters( 'tdls_pw_check_email', true );
		if ( $check_email && $user instanceof WP_User && ! empty( $user->user_email ) ) {
			$email_parts = explode( '@', $user->user_email );
			if ( ! empty( $email_parts[0] ) ) {
				$forbidden_tokens[] = strtolower( $email_parts[0] );
			}
		}

		// Site domain and site name.
		$check_site = (bool) apply_filters( 'tdls_pw_check_site_tokens', true );
		if ( $check_site ) {
			$site_url = get_site_url();
			$parsed   = wp_parse_url( $site_url );
			if ( ! empty( $parsed['host'] ) ) {
				$host_parts = explode( '.', $parsed['host'] );
				foreach ( $host_parts as $part ) {
					if ( strlen( $part ) > 2 ) {
						$forbidden_tokens[] = strtolower( $part );
					}
				}
			}

			$site_name = get_bloginfo( 'name' );
			if ( ! empty( $site_name ) ) {
				$forbidden_tokens[] = strtolower( $site_name );
			}
		}

		// Check if password contains any forbidden tokens.
		foreach ( $forbidden_tokens as $token ) {
			if ( strlen( $token ) >= 3 && false !== strpos( $password_lower, $token ) ) {
				$errors->add(
					'tdls_pw_context',
					__( 'Password contains your username, email, or site information.', 'tomatillo-design-login-security' )
				);
				return;
			}
		}

		// Common weak passwords and patterns.
		$weak_list = apply_filters(
			'tdls_pw_weak_list',
			[
				'password',
				'pass',
				'admin',
				'welcome',
				'letmein',
				'123456',
				'12345678',
				'123456789',
				'1234567890',
				'qwerty',
				'qwertyuiop',
				'asdfgh',
				'asdfghjkl',
				'zxcvbn',
				'zxcvbnm',
				'111111',
				'000000',
				'abc123',
				'password123',
				'admin123',
			]
		);

		foreach ( $weak_list as $weak ) {
			if ( false !== strpos( $password_lower, strtolower( $weak ) ) ) {
				$errors->add(
					'tdls_pw_weak',
					__( 'Password is too common or predictable.', 'tomatillo-design-login-security' )
				);
				return;
			}
		}
	}

	/* ============================================================
	 * Login attempt limiting (simple)
	 * ============================================================
	 */

	private static function get_max_attempts(): int {
		$max = (int) apply_filters( 'tdls_login_max_attempts', 5 );
		return max( 1, $max );
	}

	private static function get_lockout_seconds(): int {
		$secs = (int) apply_filters( 'tdls_login_lockout_seconds', DAY_IN_SECONDS );
		return max( 60, $secs );
	}

	private static function get_window_seconds(): int {
		$secs = (int) apply_filters( 'tdls_login_window_seconds', 900 );
		return max( 60, $secs );
	}

	private static function get_hard_lock_threshold(): int {
		$threshold = (int) apply_filters( 'tdls_login_hard_lock_threshold', 25 );
		return max( 1, $threshold );
	}

	private static function get_hard_lock_duration(): int {
		$secs = (int) apply_filters( 'tdls_login_hard_lock_duration', 15 * MINUTE_IN_SECONDS );
		return max( 60, $secs );
	}

	/**
	 * Calculate progressive throttle delay based on failure count.
	 * Filterable ladder allows custom delay steps.
	 *
	 * Default ladder:
	 * 1-2 failures: 0s
	 * 3: 2s
	 * 4: 5s
	 * 5: 15s
	 * 6+: 60s cap
	 */
	private static function calculate_throttle_delay( int $count ): int {

		$ladder = apply_filters(
			'tdls_login_throttle_ladder',
			[
				1 => 0,
				2 => 0,
				3 => 2,
				4 => 5,
				5 => 15,
			]
		);

		// Default cap for counts beyond ladder.
		$default_cap = (int) apply_filters( 'tdls_login_throttle_default_cap', 60 );

		if ( isset( $ladder[ $count ] ) ) {
			return (int) $ladder[ $count ];
		}

		// For counts beyond the ladder, use the highest defined value or default cap.
		$max_ladder_delay = ! empty( $ladder ) ? max( array_values( $ladder ) ) : 0;
		return max( $max_ladder_delay, $default_cap );
	}

	private static function use_combined_key(): bool {
		return (bool) apply_filters( 'tdls_login_use_combined_key', true );
	}

	private static function use_ip_key(): bool {
		return (bool) apply_filters( 'tdls_login_use_ip_key', true );
	}

	private static function get_client_ip(): string {

		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		$ip = apply_filters( 'tdls_login_client_ip', $ip );

		$ip = trim( (string) $ip );
		if ( '' === $ip ) {
			$ip = '0.0.0.0';
		}

		return $ip;
	}

	private static function get_prefix(): string {
		$prefix = (string) apply_filters( 'tdls_login_transient_prefix', 'tdls_ll_' );
		$prefix = preg_replace( '/[^a-zA-Z0-9_\-]/', '', $prefix );
		return $prefix ?: 'tdls_ll_';
	}

	private static function key_for_ip( string $ip ): string {
		return self::get_prefix() . 'ip_' . md5( $ip );
	}

	private static function key_for_ip_login( string $ip, string $login ): string {
		$login = sanitize_user( $login, true );
		return self::get_prefix() . 'ipl_' . md5( $ip . '|' . $login );
	}

	/**
	 * Data shape in transient:
	 * [
	 *   'count'       => int,
	 *   'lock_until'  => int (unix timestamp) or 0,
	 *   'delay_until' => int (unix timestamp) or 0,
	 *   'updated'     => int (unix timestamp),
	 * ]
	 */
	private static function get_state( string $key ): array {

		$state = get_transient( $key );
		$now   = time();

		if ( ! is_array( $state ) ) {
			return [
				'count'       => 0,
				'lock_until'  => 0,
				'delay_until' => 0,
				'updated'     => $now,
			];
		}

		$state['count']       = isset( $state['count'] ) ? (int) $state['count'] : 0;
		$state['lock_until']  = isset( $state['lock_until'] ) ? (int) $state['lock_until'] : 0;
		$state['delay_until'] = isset( $state['delay_until'] ) ? (int) $state['delay_until'] : 0;
		$state['updated']     = isset( $state['updated'] ) ? (int) $state['updated'] : $now;

		// Sliding window reset: if state is older than window, reset counts/delays.
		$window = self::get_window_seconds();
		if ( $state['updated'] < ( $now - $window ) ) {
			$state['count']       = 0;
			$state['lock_until']  = 0;
			$state['delay_until'] = 0;
			$state['updated']     = $now;
		}

		return $state;
	}

	private static function set_state( string $key, array $state ): void {
		set_transient( $key, $state, self::get_lockout_seconds() );
	}

	private static function clear_state( string $key ): void {
		delete_transient( $key );
	}

	private static function is_locked( array $state ): bool {
		return (int) $state['lock_until'] > time();
	}

	private static function is_throttled( array $state ): bool {
		return (int) $state['delay_until'] > time();
	}

	private static function seconds_remaining( array $state ): int {
		return max( 0, (int) $state['lock_until'] - time() );
	}

	private static function throttle_seconds_remaining( array $state ): int {
		return max( 0, (int) $state['delay_until'] - time() );
	}

	/**
	 * If locked or throttled, block authentication immediately.
	 * IMPORTANT: Do not typehint $username/$password as string (can be null in some flows).
	 */
	public static function maybe_block_locked_out_login( $user, $username, $password ) {

		if ( is_wp_error( $user ) ) {
			return $user;
		}

		$username = (string) $username;
		$ip       = self::get_client_ip();

		$locked_seconds    = 0;
		$throttled_seconds = 0;

		if ( self::use_ip_key() ) {
			$ip_state = self::get_state( self::key_for_ip( $ip ) );
			if ( self::is_locked( $ip_state ) ) {
				$locked_seconds = max( $locked_seconds, self::seconds_remaining( $ip_state ) );
			}
			if ( self::is_throttled( $ip_state ) ) {
				$throttled_seconds = max( $throttled_seconds, self::throttle_seconds_remaining( $ip_state ) );
			}
		}

		if ( self::use_combined_key() && '' !== $username ) {
			$ipl_state = self::get_state( self::key_for_ip_login( $ip, $username ) );
			if ( self::is_locked( $ipl_state ) ) {
				$locked_seconds = max( $locked_seconds, self::seconds_remaining( $ipl_state ) );
			}
			if ( self::is_throttled( $ipl_state ) ) {
				$throttled_seconds = max( $throttled_seconds, self::throttle_seconds_remaining( $ipl_state ) );
			}
		}

		// Hard lock takes precedence.
		if ( $locked_seconds > 0 ) {
			// Used only to show a friendly error message; short TTL; scoped per-IP.
			$msg_key = self::get_prefix() . 'lastmsg_ip_' . md5( $ip );
			set_transient( $msg_key, $locked_seconds, 60 );

			return new WP_Error(
				'tdls_login_locked',
				__( 'Too many failed login attempts. Please try again later.', 'tomatillo-design-login-security' )
			);
		}

		// Progressive throttle.
		if ( $throttled_seconds > 0 ) {
			// Store throttle time per-IP (optional, for customization).
			$msg_key = self::get_prefix() . 'lastmsg_ip_' . md5( $ip );
			set_transient( $msg_key, $throttled_seconds, 60 );

			return new WP_Error(
				'tdls_login_throttled',
				__( 'Too many failed login attempts. Please try again in a moment.', 'tomatillo-design-login-security' )
			);
		}

		return $user;
	}

	/**
	 * Record failed attempts and apply progressive throttling or hard lock after threshold.
	 */
	public static function record_failed_login( $username ): void {

		$username = (string) $username;

		$max              = self::get_max_attempts();
		$lock             = self::get_lockout_seconds();
		$hard_threshold   = self::get_hard_lock_threshold();
		$hard_lock_duration = self::get_hard_lock_duration();
		$ip               = self::get_client_ip();
		$now              = time();

		// 1) IP-only tracking.
		if ( self::use_ip_key() ) {

			$key   = self::key_for_ip( $ip );
			$state = self::get_state( $key );

			// If already locked or throttled, do not extend (DoS prevention).
			if ( self::is_locked( $state ) || self::is_throttled( $state ) ) {
				return;
			}

			// If lock expired, reset (already handled by get_state with window logic, but keep explicit check).
			if ( (int) $state['lock_until'] <= $now ) {
				$state['count']      = 0;
				$state['lock_until'] = 0;
			}

			$state['count']   = (int) $state['count'] + 1;
			$state['updated'] = $now;

			// Apply progressive throttle.
			$throttle_delay         = self::calculate_throttle_delay( $state['count'] );
			$state['delay_until']   = $now + $throttle_delay;

			// Emergency hard lock backstop.
			if ( $state['count'] >= $hard_threshold ) {
				$state['lock_until'] = $now + $hard_lock_duration;
			}

			self::set_state( $key, $state );
		}

		// 2) IP + username tracking.
		if ( self::use_combined_key() && '' !== $username ) {

			$key   = self::key_for_ip_login( $ip, $username );
			$state = self::get_state( $key );

			// If already locked or throttled, do not extend (DoS prevention).
			if ( self::is_locked( $state ) || self::is_throttled( $state ) ) {
				return;
			}

			if ( (int) $state['lock_until'] <= $now ) {
				$state['count']      = 0;
				$state['lock_until'] = 0;
			}

			$state['count']   = (int) $state['count'] + 1;
			$state['updated'] = $now;

			// Apply progressive throttle.
			$throttle_delay         = self::calculate_throttle_delay( $state['count'] );
			$state['delay_until']   = $now + $throttle_delay;

			// Emergency hard lock backstop.
			if ( $state['count'] >= $hard_threshold ) {
				$state['lock_until'] = $now + $hard_lock_duration;
			}

			self::set_state( $key, $state );
		}
	}

	/**
	 * On successful login, clear attempts for this IP and this IP+username.
	 */
	public static function clear_attempts_on_success( string $user_login, WP_User $user ): void {

		$ip = self::get_client_ip();

		if ( self::use_ip_key() ) {
			self::clear_state( self::key_for_ip( $ip ) );
		}

		if ( self::use_combined_key() ) {
			self::clear_state( self::key_for_ip_login( $ip, $user_login ) );
		}
	}

	/**
	 * Optional: show approximate remaining lockout time.
	 */
	public static function maybe_customize_login_error( string $errors ): string {

		$ip      = self::get_client_ip();
		$msg_key = self::get_prefix() . 'lastmsg_ip_' . md5( $ip );
		$remaining = (int) get_transient( $msg_key );
		if ( $remaining <= 0 ) {
			return $errors;
		}

		$hours = (int) ceil( $remaining / HOUR_IN_SECONDS );

		$msg = sprintf(
			_n(
				'Too many failed login attempts. Try again in about %d hour.',
				'Too many failed login attempts. Try again in about %d hours.',
				$hours,
				'tomatillo-design-login-security'
			),
			$hours
		);

		return esc_html( $msg );
	}
}

Tomatillo_Design_Login_Security::init();
