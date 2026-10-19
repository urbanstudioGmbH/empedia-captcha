/* EMPEDIAcloud – check existing comments with the content check, in small rounds with progress. */
( function () {
	'use strict';
	var cfg = window.EmpediaComments;
	var btn = document.getElementById( 'empedia-cc-start' );
	var msg = document.getElementById( 'empedia-cc-msg' );
	var scope = document.getElementById( 'empedia-cc-scope' );
	if ( ! cfg || ! btn || ! msg || ! scope ) {
		return;
	}
	function fmt( text, a, b ) {
		return text.replace( '%1$d', a ).replace( '%2$d', b );
	}
	function round( last, checked, flagged ) {
		var body = new URLSearchParams();
		body.set( 'action', 'empedia_cloud_comments_check' );
		body.set( 'nonce', cfg.nonce );
		body.set( 'scope', scope.value );
		body.set( 'last_id', String( last ) );
		fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } )
			.then( function ( r ) {
				return r.json().then( function ( j ) {
					return { status: r.status, json: j };
				} );
			} )
			.then( function ( res ) {
				if ( ! res.json.success ) {
					var code = res.json.data && res.json.data.code;
					msg.textContent = fmt( cfg.i18n.progress, checked, flagged ) + ' ' + ( 'unreachable' === code ? cfg.i18n.unreachable : cfg.i18n.error );
					btn.disabled = false;
					return;
				}
				var d = res.json.data;
				checked += d.checked;
				flagged += d.flagged;
				if ( d.done ) {
					msg.textContent = fmt( cfg.i18n.done, checked, flagged );
					btn.disabled = false;
					return;
				}
				msg.textContent = fmt( cfg.i18n.progress, checked, flagged );
				round( d.last_id, checked, flagged );
			} )
			.catch( function () {
				msg.textContent = cfg.i18n.error;
				btn.disabled = false;
			} );
	}
	btn.addEventListener( 'click', function () {
		if ( ! window.confirm( cfg.i18n.confirm ) ) {
			return;
		}
		btn.disabled = true;
		msg.textContent = '…';
		round( 0, 0, 0 );
	} );
}() );
