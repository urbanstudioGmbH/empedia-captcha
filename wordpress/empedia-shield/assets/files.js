/* EMPEDIAcloud – file check: start and follow the scan on the settings tab “Files”. */
( function () {
	'use strict';
	var cfg = window.EmpediaFiles;
	var btn = document.getElementById( 'empedia-files-start' );
	var msg = document.getElementById( 'empedia-files-msg' );
	if ( ! cfg || ! btn || ! msg ) {
		return;
	}
	function post( action ) {
		var body = new URLSearchParams();
		body.set( 'action', action );
		body.set( 'nonce', cfg.nonce );
		return fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) {
			return r.json();
		} );
	}
	function poll() {
		post( 'empedia_cloud_files_poll' ).then( function ( res ) {
			if ( ! res.success ) { throw new Error( 'x' ); }
			if ( res.data.running ) {
				msg.textContent = res.data.label || '';
				window.setTimeout( poll, 3000 );
			} else {
				window.location.reload();
			}
		} ).catch( function () {
			msg.textContent = cfg.i18n.error;
			btn.disabled = false;
		} );
	}
	btn.addEventListener( 'click', function () {
		btn.disabled = true;
		msg.textContent = cfg.i18n.starting;
		post( 'empedia_cloud_files_start' ).then( function ( res ) {
			if ( ! res.success ) { throw new Error( 'x' ); }
			window.setTimeout( poll, 1500 );
		} ).catch( function () {
			msg.textContent = cfg.i18n.error;
			btn.disabled = false;
		} );
	} );
	if ( cfg.running ) {
		btn.disabled = true;
		poll();
	}
}() );
