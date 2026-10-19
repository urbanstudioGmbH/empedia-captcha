/* EMPEDIAcloud – backups: start and follow a backup or restore on the tab “Backups”. */
( function () {
	'use strict';
	var cfg = window.EmpediaBackup;
	var btn = document.getElementById( 'empedia-backup-start' );
	var msg = document.getElementById( 'empedia-backup-msg' );
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
		post( 'empedia_cloud_backup_poll' ).then( function ( res ) {
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
		post( 'empedia_cloud_backup_start' ).then( function ( res ) {
			if ( ! res.success ) {
				msg.textContent = ( res.data && res.data.message ) || cfg.i18n.error;
				btn.disabled = false;
				return;
			}
			window.setTimeout( poll, 1500 );
		} ).catch( function () {
			msg.textContent = cfg.i18n.error;
			btn.disabled = false;
		} );
	} );
	document.querySelectorAll( 'form.empedia-restore' ).forEach( function ( f ) {
		f.addEventListener( 'submit', function ( e ) {
			if ( ! window.confirm( cfg.i18n.confirm ) ) { e.preventDefault(); }
		} );
	} );
	document.querySelectorAll( '.empedia-del' ).forEach( function ( b ) {
		b.addEventListener( 'click', function ( e ) {
			if ( ! window.confirm( cfg.i18n.delete ) ) { e.preventDefault(); }
		} );
	} );
	var sel = document.getElementById( 'empedia-target-type' );
	if ( sel ) {
		sel.addEventListener( 'change', function () {
			document.querySelectorAll( 'form.empedia-target-form' ).forEach( function ( f ) {
				if ( ! f.querySelector( 'input[name="tid"]' ).value ) {
					f.style.display = f.getAttribute( 'data-type' ) === sel.value ? '' : 'none';
				}
			} );
		} );
	}
	if ( cfg.running ) {
		btn.disabled = true;
		poll();
	}
}() );
