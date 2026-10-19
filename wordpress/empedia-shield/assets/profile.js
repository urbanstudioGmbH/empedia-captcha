/* EMPEDIAcloud – QR code for the authenticator app on the profile page. */
( function () {
	'use strict';
	var img = document.getElementById( 'empedia-totp-qr' );
	if ( ! img || ! window.qrcode ) {
		return;
	}
	try {
		var qr = window.qrcode( 0, 'M' );
		qr.addData( img.getAttribute( 'data-uri' ) );
		qr.make();
		img.src = qr.createDataURL( 5, 2 );
		img.style.display = '';
	} catch ( e ) {
		img.style.display = 'none';
	}
}() );
