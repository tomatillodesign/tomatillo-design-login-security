<?php
/**
 * Plugin Name: Tomatillo Design – Login Security
 * Description: Enforces strong WordPress passwords, removes weak password bypass, and limits login attempts (simple lockout).
 * Version: 1.1.1
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
 *     return 'tdls_ll_'; // default 'tdls_ll_' (change if needed)
 * });
 *
 * IMPORTANT (reverse proxy/CDN):
 * By default we use $_SERVER['REMOTE_ADDR'].
 * If your site is behind Cloudflare / a reverse proxy, you may need to override IP detection:
 *
 * add_filter( 'tdls_login_client_ip', function( $ip ) {
 *     // Example ONLY — use *trusted* headers for your environment.
 *     // return isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? $_SERVER['HTTP_CF_CONNECTING_IP'] : $ip;
 *     return $ip;
 * });
 *
 * ABOUT "bot hammers my username from other IPs":
 * This plugin does NOT do a global username lockout by default (to avoid easy DoS).
 * Lockouts are per-IP and per-IP+username, so attackers lock themselves out, not you.
 */

final class Tomatillo_Design_Login_Security {

	const VERSION = '1.1.1';

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
		wp_add_inline_script(
			'password-strength-meter',
			"jQuery(function($){
				function tdlsRemoveWeak(){ $('.pw-weak').remove(); }
				tdlsRemoveWeak();
				$(document).on('ajaxComplete', tdlsRemoveWeak);
			});"
		);
	}

	public static function enforce_strong_password_on_profile_save( WP_Error $errors, bool $update, WP_User $user ): void {
		$pass1 = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
		if ( '' === $pass1 ) {
			return;
		}

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

	private static function validate_password_or_add_errors( string $password, WP_Error $errors ): void {
		$password = (string) $password;

		if ( strlen( $password ) < 12 ) {
			$errors->add( 'tdls_pw_length', __( 'Password must be at least 12 characters long.', 'tomatillo-design-login-security' ) );
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
			$errors->add( 'tdls_pw_whitespace', __( 'Password cannot begin or end with whitespace.', 'tomatillo-design-login-security' ) );
		}
	}

	/* ============================================================
	 * Login attempt limiting
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

	private static function get_state( string $key ): array {
		$state = get_transient( $key );
		if ( ! is_array( $state ) ) {
			$state = [
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
		return ( isset( $state['lock_until'] ) && (int) $state['lock_until'] > time() );
	}

	private static function seconds_remaining( array $state ): int {
		$until = isset( $state['lock_until'] ) ? (int) $state['lock_until'] : 0;
		return max( 0, $until - time() );
	}

	public static function maybe_block_locked_out_login( $user, string $username, string $password ) {

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
			set_transient( self::get_prefix() . 'last_lock_msg', $locked_seconds, 60 );

			return new WP_Error(
				'tdls_login_locked',
				__( 'Too many failed login attempts. Please try again later.', 'tomatillo-design-login-security' )
			);
		}

		return $user;
	}

	public static function record_failed_login( string $username ): void {

		$max  = self::get_max_attempts();
		$lock = self::get_lockout_seconds();
		$ip   = self::get_client_ip();
		$now  = time();

		if ( self::use_ip_key() ) {
			$key   = self::key_for_ip( $ip );
			$state = self::get_state( $key );

			if ( (int) $state['lock_until'] <= $now ) {
				$state['count']      = 0;
				$state['lock_until'] = 0;
			}

			$state['count']   = (int) $state['count'] + 1;
			$state['updated'] = $now;

			if ( $state['count'] >= $max ) {
				$state['lock_until'] = $now + $lock;
				$state['count']      = $max;
			}

			self::set_state( $key, $state );
		}

		if ( self::use_combined_key() && '' !== (string) $username ) {
			$key   = self::key_for_ip_login( $ip, (string) $username );
			$state = self::get_state( $key );

			if ( (int) $state['lock_until'] <= $now ) {
				$state['count']      = 0;
				$state['lock_until'] = 0;
			}

			$state['count']   = (int) $state['count'] + 1;
			$state['updated'] = $now;

			if ( $state['count'] >= $max ) {
				$state['lock_until'] = $now + $lock;
				$state['count']      = $max;
			}

			self::set_state( $key, $state );
		}
	}

	public static function clear_attempts_on_success( string $user_login, WP_User $user ): void {
		$ip = self::get_client_ip();

		if ( self::use_ip_key() ) {
			self::clear_state( self::key_for_ip( $ip ) );
		}

		if ( self::use_combined_key() ) {
			self::clear_state( self::key_for_ip_login( $ip, $user_login ) );
		}
	}

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
