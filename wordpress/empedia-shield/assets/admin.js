/* EMPEDIAcloud – security scan button on the settings page. */
( function () {
	'use strict';
	var btn = document.getElementById( 'empedia-scan' );
	var box = document.getElementById( 'empedia-scan-msg' );
	if ( ! btn || ! box || ! window.EmpediaCloud ) {
		return;
	}
	var cfg = window.EmpediaCloud;
	var p = box.querySelector( 'p' );

	function show( cls, text, link ) {
		box.className = 'notice inline notice-' + cls;
		box.style.display = '';
		p.textContent = text;
		if ( link ) {
			var a = document.createElement( 'a' );
			a.href = link;
			a.target = '_blank';
			a.rel = 'noopener noreferrer';
			a.textContent = ' ' + cfg.i18n.report;
			p.appendChild( a );
		}
	}

	function post( action, data ) {
		var body = new URLSearchParams();
		body.set( 'action', action );
		body.set( 'nonce', cfg.nonce );
		Object.keys( data || {} ).forEach( function ( k ) { body.set( k, data[ k ] ); } );
		return fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) { return r.json(); } );
	}

	function poll( job, started ) {
		// Polls every 10 seconds for at most 40 minutes.
		if ( Date.now() - started > 40 * 60 * 1000 ) {
			show( 'warning', cfg.i18n.failed );
			btn.disabled = false;
			return;
		}
		post( 'empedia_cloud_scan_poll', { job: job } ).then( function ( r ) {
			if ( ! r.success ) {
				show( 'error', ( r.data && r.data.message ) || cfg.i18n.error );
				btn.disabled = false;
				return;
			}
			var s = r.data.status;
			if ( 'completed' === s ) {
				show( 'success', cfg.i18n.done, r.data.report );
				btn.disabled = false;
			} else if ( 'failed' === s || 'cancelled' === s ) {
				show( 'error', cfg.i18n.failed );
				btn.disabled = false;
			} else {
				show( 'info', cfg.i18n.running );
				setTimeout( function () { poll( job, started ); }, 10000 );
			}
		} ).catch( function () {
			// A short network error should not end the polling.
			setTimeout( function () { poll( job, started ); }, 15000 );
		} );
	}

	btn.addEventListener( 'click', function () {
		btn.disabled = true;
		show( 'info', cfg.i18n.starting );
		post( 'empedia_cloud_scan_start' ).then( function ( r ) {
			if ( ! r.success || ! r.data.job ) {
				show( 'error', ( r.data && r.data.message ) || cfg.i18n.error );
				btn.disabled = false;
				return;
			}
			poll( r.data.job, Date.now() );
		} ).catch( function () {
			show( 'error', cfg.i18n.error );
			btn.disabled = false;
		} );
	} );
}() );
