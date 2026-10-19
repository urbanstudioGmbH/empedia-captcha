<?php
/**
 * Backup status report: a small summary of the backup state for EMPEDIAcloud ( monitoring and alerts ).
 *
 * Only technical facts leave the site: schedule, scope, timestamps, sizes, counts, error codes and, per storage target, its type and
 * whether the last upload worked. Never access data, host names, folders or file names.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Backup_Report {

	/** Error codes are short identifiers; anything else is reduced to 'unknown'. */
	private static function code( $v ) {
		$v = strtolower( (string) $v );
		return preg_match( '/^[a-z0-9_]{1,24}$/', $v ) ? $v : ( '' === $v ? '' : 'unknown' );
	}

	/** @return array summary for the inventory and the heartbeat */
	public static function summary() {
		$set   = Empedia_Cloud_Backup::settings();
		$idx   = Empedia_Cloud_Backup::index();
		$state = Empedia_Cloud_Backup::state();

		$last = null;
		foreach ( $idx as $e ) {
			if ( isset( $e['created'] ) && ( ! $last || (int) $e['created'] > (int) $last['created'] ) ) {
				$last = $e;
			}
		}

		$error_at = 0;
		$error    = '';
		if ( $state && 'failed' === $state['phase'] && ! empty( $state['finished'] ) ) {
			$error_at = (int) $state['finished'];
			$error    = self::code( isset( $state['error'] ) ? $state['error'] : '' );
			$error    = '' === $error ? 'unknown' : $error;
		}

		// Storage targets: the EMPEDIAcloud storage and every enabled target of the site ( type and short name only ).
		$remote_on = ! empty( $set['remote'] );
		$failed    = array();
		if ( $state && 'done' === $state['phase'] && ! empty( $state['remote_error'] ) ) {
			$failed = array_filter( array_map( 'trim', explode( ',', (string) $state['remote_error'] ) ) );
		}
		$ids = array();
		if ( Empedia_Cloud_Bunny::has_zone() ) {
			$ids['cloud'] = array( 'type' => 'cloud', 'error' => '' );
		}
		foreach ( Empedia_Cloud_Targets::listing() as $tid => $t ) {
			if ( ! empty( $t['enabled'] ) ) {
				$ids[ $tid ] = array( 'type' => (string) $t['type'], 'error' => ! empty( $t['error'] ) ? 'test' : '' );
			}
		}
		$targets = array();
		foreach ( array_slice( $ids, 0, 12, true ) as $tid => $t ) {
			$at = 0;
			foreach ( $idx as $e ) {
				if ( ! empty( $e['remote'] ) && in_array( $tid, (array) $e['remote'], true ) ) {
					$at = max( $at, (int) $e['created'] );
				}
			}
			$err = '';
			if ( $remote_on ) {
				$err = in_array( $tid, $failed, true ) ? 'upload' : $t['error'];
			}
			$targets[] = array(
				'id'         => substr( preg_replace( '/[^A-Za-z0-9_-]/', '', (string) $tid ), 0, 40 ),
				'type'       => preg_replace( '/[^a-z0-9_-]/', '', strtolower( $t['type'] ) ),
				'ok'         => '' === $err,
				'last_ok_at' => $at,
				'error'      => $err,
			);
		}

		$rs = Empedia_Cloud_Restore::state();
		return array(
			'schedule'        => $set['schedule'],
			'scope'           => $set['scope'],
			'encrypted'       => $last ? ! empty( $last['encrypted'] ) : (bool) $set['encrypt'],
			'last_ok_at'      => $last ? (int) $last['created'] : 0,
			'last_ok_size'    => $last && isset( $last['size'] ) ? max( 0, (int) $last['size'] ) : 0,
			'last_error_at'   => $error_at,
			'last_error'      => $error,
			'count'           => count( $idx ),
			'targets'         => $targets,
			'restore_last_at' => $rs && ! empty( $rs['finished'] ) ? (int) $rs['finished'] : 0,
			'restore_ok'      => $rs && ! empty( $rs['finished'] ) ? 'done' === $rs['phase'] : null,
		);
	}
}
