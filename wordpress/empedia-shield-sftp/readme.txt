=== EMPEDIA Shield SFTP ===
Contributors: urbanstudio
Tags: backup, sftp, ssh, empedia
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Requires Plugins: empedia-shield
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Adds SFTP (SSH) as a storage target for the encrypted backups of EMPEDIA Shield.

== Description ==

EMPEDIA Shield backs up your site and can store the encrypted backups on your own storage: S3-compatible storage, WebDAV and FTP/FTPS are built in. This add-on adds **SFTP (SSH)**. It brings its own SSH library (phpseclib 3, MIT licence) – that is why it is a separate plugin and not part of EMPEDIA Shield.

* Login with password or private key (OpenSSH or PEM, with passphrase).
* The server key is checked: enter the SHA256 fingerprint, or leave it empty and the fingerprint of the first connection is remembered (trust on first use); a changed key stops the connection.
* Uses the PHP extension ssh2 when it is available and no private key is needed, otherwise the bundled library.
* Works with all backup functions of EMPEDIA Shield: schedule, encryption, restore from the target, keeping the last backups.
* Existing SFTP targets that were saved in earlier versions of EMPEDIA Shield work again as soon as this add-on is active.

It needs EMPEDIA Shield 1.8.0 or newer. This add-on is delivered from https://empedia.cloud (WordPress → Download) and updates itself from there; it is not distributed through wordpress.org.

== External services ==

This add-on connects only to the SFTP server that you enter in the backup settings of EMPEDIA Shield, to store and read your encrypted backup files. It sends nothing to EMPEDIAcloud except the update check below.

**Update check** – at most every 12 hours the add-on asks https://empedia.cloud/api/public/plugin-updates/empedia-shield-sftp whether a newer version exists. Only the plugin name is part of the request; the downloaded package is checked with a SHA-256 hash (and a signature) before it is installed. Privacy: https://empedia.cloud/datenschutz.html

== Installation ==

1. Install and activate EMPEDIA Shield 1.8.0 or newer.
2. Upload this add-on on the Plugins screen (Add New → Upload) and activate it.
3. Open EMPEDIA Shield → Backups → Add a storage target and choose “SFTP (SSH)”.

== Frequently Asked Questions ==

= Why is SFTP not part of EMPEDIA Shield? =

The SSH library is a large third-party package. EMPEDIA Shield for the wordpress.org directory ships without bundled libraries.

= Is a connection to EMPEDIAcloud needed? =

No. The SFTP target works on your site alone.

== Changelog ==

= 1.0.0 =
* First release. The SFTP target was part of EMPEDIA Shield until version 1.7.0; saved targets are kept.
