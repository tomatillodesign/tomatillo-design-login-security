<?php
/**
 * Plugin Name: Tomatillo Design – Login Security
 * Description: Enforces strong WordPress passwords, removes weak password bypass, and limits login attempts (simple lockout).
 * Version: 1.0
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
 * add_filter( 'tdls_login_max_attempts', function() {
 *     return 5; // default 5
 * });
 *
 * add_filter( 'tdls_login_lockout_seconds', function() {
 *     return 24 * HOUR_IN_SECONDS; // default 86400 (24h)
 * });
 *
 * add_filter( 'tdls_login_use_ip_key', function() {
 *     return true; // default true (locks out an IP after too many failures)
 * });
 *
 * add_filter( 'tdls_login_use_combined_key', function() {
 *     return true; // default true (locks out IP+username combo too)
 * });
 *
 * add_filter( 'tdls_login_transient_prefix', function() {
 *     return 'tdls_ll_'; // default 'tdls_ll_'
 * });
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
 * Lockouts are per-IP and per-IP+username by default.
 */

final class Tomatillo_Design_Login_Security {

	const VERSION = '1.1.2';

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

		self::validate_password_or_add_errors( $pass1, $errors );
	}

	public static function enforce_strong_password_on_reset( WP_Error $errors, WP_User $user ): WP_Error {

		$pass1 = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
		if ( '' === $pass1 ) {
			return $errors;
		}

		self::validate_password_or_add_errors( $pass1, $errors );
		return $errors;
	}

	/**
	 * Password rules:
	 * - 12+ characters
	 * - must include uppercase, lowercase, number, special char
	 */
	private static function validate_password_or_add_errors( string $password, WP_Error $errors ): void {

		$password = (string) $password;

		if ( strlen( $password ) < 12 ) {
			$errors->add(
				'tdls_pw_length',
				__( 'Password must be at least 12 characters long.', 'tomatillo-design-login-security' )
			);
		}

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

		if ( $password !== trim( $password ) ) {
			$errors->add(
				'tdls_pw_whitespace',
				__( 'Password cannot begin or end with whitespace.', 'tomatillo-design-login-security' )
			);
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
	 *   'count'      => int,
	 *   'lock_until' => int (unix timestamp) or 0,
	 *   'updated'    => int (unix timestamp),
	 * ]
	 */
	private static function get_state( string $key ): array {

		$state = get_transient( $key );

		if ( ! is_array( $state ) ) {
			return [
				'count'      => 0,
				'lock_until' => 0,
				'updated'    => time(),
			];
		}

		$state['count']      = isset( $state['count'] ) ? (int) $state['count'] : 0;
		$state['lock_until'] = isset( $state['lock_until'] ) ? (int) $state['lock_until'] : 0;
		$state['updated']    = isset( $state['updated'] ) ? (int) $state['updated'] : time();

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

	private static function seconds_remaining( array $state ): int {
		return max( 0, (int) $state['lock_until'] - time() );
	}

	/**
	 * If locked, block authentication immediately.
	 * IMPORTANT: Do not typehint $username/$password as string (can be null in some flows).
	 */
	public static function maybe_block_locked_out_login( $user, $username, $password ) {

		if ( is_wp_error( $user ) ) {
			return $user;
		}

		$username = (string) $username;
		$ip       = self::get_client_ip();

		$locked_seconds = 0;

		if ( self::use_ip_key() ) {
			$ip_state = self::get_state( self::key_for_ip( $ip ) );
			if ( self::is_locked( $ip_state ) ) {
				$locked_seconds = max( $locked_seconds, self::seconds_remaining( $ip_state ) );
			}
		}

		if ( self::use_combined_key() && '' !== $username ) {
			$ipl_state = self::get_state( self::key_for_ip_login( $ip, $username ) );
			if ( self::is_locked( $ipl_state ) ) {
				$locked_seconds = max( $locked_seconds, self::seconds_remaining( $ipl_state ) );
			}
		}

		if ( $locked_seconds > 0 ) {
			// Used only to show a friendly error message; short TTL.
			set_transient( self::get_prefix() . 'last_lock_msg', $locked_seconds, 60 );

			return new WP_Error(
				'tdls_login_locked',
				__( 'Too many failed login attempts. Please try again later.', 'tomatillo-design-login-security' )
			);
		}

		return $user;
	}

	/**
	 * Record failed attempts and lock after threshold.
	 */
	public static function record_failed_login( $username ): void {

		$username = (string) $username;

		$max  = self::get_max_attempts();
		$lock = self::get_lockout_seconds();
		$ip   = self::get_client_ip();
		$now  = time();

		// 1) IP-only tracking.
		if ( self::use_ip_key() ) {

			$key   = self::key_for_ip( $ip );
			$state = self::get_state( $key );

			// If lock expired, reset.
			if ( (int) $state['lock_until'] <= $now ) {
				$state['count']      = 0;
				$state['lock_until'] = 0;
			}

			$state['count']   = (int) $state['count'] + 1;
			$state['updated'] = $now;

			if ( $state['count'] >= $max ) {
				$state['count']      = $max;
				$state['lock_until'] = $now + $lock;
			}

			self::set_state( $key, $state );
		}

		// 2) IP + username tracking.
		if ( self::use_combined_key() && '' !== $username ) {

			$key   = self::key_for_ip_login( $ip, $username );
			$state = self::get_state( $key );

			if ( (int) $state['lock_until'] <= $now ) {
				$state['count']      = 0;
				$state['lock_until'] = 0;
			}

			$state['count']   = (int) $state['count'] + 1;
			$state['updated'] = $now;

			if ( $state['count'] >= $max ) {
				$state['count']      = $max;
				$state['lock_until'] = $now + $lock;
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

		$remaining = (int) get_transient( self::get_prefix() . 'last_lock_msg' );
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
