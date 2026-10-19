/* EMPEDIAcloud – passkeys in the browser: sign-in, second factor and registration ( profile page ). */
( function () {
	'use strict';
	var cfg = window.EmpediaPasskey;
	if ( ! cfg ) {
		return;
	}

	function b64uToBuf( s ) {
		s = s.replace( /-/g, '+' ).replace( /_/g, '/' );
		while ( s.length % 4 ) { s += '='; }
		var bin = atob( s ), out = new Uint8Array( bin.length );
		for ( var i = 0; i < bin.length; i++ ) { out[ i ] = bin.charCodeAt( i ); }
		return out.buffer;
	}
	function bufToB64u( buf ) {
		var b = new Uint8Array( buf ), s = '';
		for ( var i = 0; i < b.length; i++ ) { s += String.fromCharCode( b[ i ] ); }
		return btoa( s ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}
	function post( data ) {
		var body = new URLSearchParams();
		Object.keys( data ).forEach( function ( k ) { body.set( k, data[ k ] ); } );
		return fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) {
			return r.json().catch( function () { return { success: false }; } );
		} );
	}
	function fail( msg ) {
		window.alert( msg || cfg.i18n.failed );
	}
	function creds( list ) {
		return ( list || [] ).map( function ( c ) { return { type: c.type, id: b64uToBuf( c.id ) }; } );
	}
	function getAssertion( opts ) {
		var pk = opts.publicKey;
		pk.challenge = b64uToBuf( pk.challenge );
		pk.allowCredentials = creds( pk.allowCredentials );
		return navigator.credentials.get( { publicKey: pk } ).then( function ( c ) {
			var r = c.response;
			return {
				id: c.id,
				clientDataJSON: bufToB64u( r.clientDataJSON ),
				authenticatorData: bufToB64u( r.authenticatorData ),
				signature: bufToB64u( r.signature ),
				userHandle: r.userHandle ? bufToB64u( r.userHandle ) : ''
			};
		} );
	}
	function submitTo( url, fields ) {
		var f = document.createElement( 'form' );
		f.method = 'post';
		f.action = url;
		Object.keys( fields ).forEach( function ( k ) {
			var i = document.createElement( 'input' );
			i.type = 'hidden';
			i.name = k;
			i.value = fields[ k ];
			f.appendChild( i );
		} );
		document.body.appendChild( f );
		f.submit();
	}

	document.addEventListener( 'click', function ( e ) {
		var t = e.target.closest ? e.target.closest( '#empedia-pk-login, #empedia-pk-2fa, #empedia-pk-add' ) : null;
		if ( ! t ) {
			return;
		}
		e.preventDefault();
		if ( ! window.PublicKeyCredential || ! navigator.credentials ) {
			fail( cfg.i18n.unsupported );
			return;
		}
		t.disabled = true;
		var done = function () { t.disabled = false; };

		if ( 'empedia-pk-login' === t.id ) {
			post( { action: 'empedia_cloud_pk_options', purpose: 'login' } ).then( function ( res ) {
				if ( ! res.success ) { throw new Error( ( res.data && res.data.message ) || '' ); }
				return getAssertion( res.data ).then( function ( resp ) {
					var form = document.getElementById( 'loginform' );
					var redirect = form && form.elements.redirect_to ? form.elements.redirect_to.value : '';
					var remember = form && form.elements.rememberme && form.elements.rememberme.checked ? '1' : '';
					submitTo( cfg.loginUrl, { empedia_pk: JSON.stringify( resp ), pk_ticket: res.data.ticket, redirect_to: redirect, rememberme: remember } );
				} );
			} ).catch( function ( err ) { done(); fail( err && err.message ? err.message : '' ); } );
		} else if ( 'empedia-pk-2fa' === t.id ) {
			post( { action: 'empedia_cloud_pk_options', purpose: '2fa', ticket: t.getAttribute( 'data-ticket' ) } ).then( function ( res ) {
				if ( ! res.success ) { throw new Error( '' ); }
				return getAssertion( res.data ).then( function ( resp ) {
					document.getElementById( 'empedia_pk' ).value = JSON.stringify( resp );
					document.getElementById( 'empedia_pk_ticket' ).value = res.data.ticket;
					document.getElementById( 'empedia2fa' ).submit();
				} );
			} ).catch( function () { done(); fail(); } );
		} else {
			var name = ( document.getElementById( 'empedia-pk-name' ) || {} ).value || '';
			post( { action: 'empedia_cloud_pk_options', purpose: 'register', nonce: cfg.nonce } ).then( function ( res ) {
				if ( ! res.success ) { throw new Error( ( res.data && res.data.message ) || '' ); }
				var pk = res.data.publicKey;
				pk.challenge = b64uToBuf( pk.challenge );
				pk.user.id = b64uToBuf( pk.user.id );
				pk.excludeCredentials = creds( pk.excludeCredentials );
				return navigator.credentials.create( { publicKey: pk } ).then( function ( c ) {
					return post( {
						action: 'empedia_cloud_pk_register',
						nonce: cfg.nonce,
						ticket: res.data.ticket,
						name: name,
						attachment: c.authenticatorAttachment || '',
						id: c.id,
						clientDataJSON: bufToB64u( c.response.clientDataJSON ),
						attestationObject: bufToB64u( c.response.attestationObject )
					} );
				} );
			} ).then( function ( fin ) {
				if ( ! fin.success ) { throw new Error( '' ); }
				var codes = fin.data && fin.data.codes ? fin.data.codes : [];
				if ( codes.length ) {
					// shown once: the page reloads after the person confirmed
					window.alert( cfg.i18n.codes + '\n\n' + codes.join( '\n' ) );
				}
				window.location.reload();
			} ).catch( function ( err ) { done(); fail( err && err.message ? err.message : '' ); } );
		}
	} );
}() );
