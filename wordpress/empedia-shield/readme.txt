=== EMPEDIA Shield ===
Contributors: urbanstudiogmbh
Tags: security, firewall, two-factor, backup, login
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.8.6
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security settings, two-factor and passkeys, file check, firewall, encrypted backups and bot protection. Optional EMPEDIAcloud connection.

== Description ==

EMPEDIA Shield protects your WordPress site in one plugin. Everything below works on your own site, without an account.

**Included, no account needed**

* **Security settings** with “Secure now” buttons that can be undone: no PHP in the uploads folder, file editor off, debug log protected, user list hidden in the REST API, XML-RPC off, version hidden, security headers, neutral sign-in errors and more. Nothing touches `wp-config.php`; file based settings only write a clearly marked block into an `.htaccess` file and remove it again when you revert.
* **Sign-in protection:** blocks addresses after too many failed attempts, two-factor authentication with an authenticator app and recovery codes, passkeys (WebAuthn) as second factor or for password-free sign-in, second factor required for chosen roles.
* **File integrity check:** compares WordPress core and wordpress.org plugins with the official checksums, finds PHP files in the uploads folder and searches code without checksums for well-known backdoor patterns. Findings are hints to check, never a statement that the site is infected.
* **Firewall** (starts in observe mode, nothing is blocked until you decide): checks requests for SQL injection, script injection, file inclusion, PHP uploads, attack tools, probing, XML-RPC abuse and too many requests.
* **Backups** of files and database on your own server (manual, daily or weekly), optional encryption, download, restore with an automatic safety copy of the database. Optional storage targets that work on your site alone, without an account: S3-compatible storage, WebDAV (Nextcloud, ownCloud) and FTP/FTPS. SFTP is available through the separate add-on plugin “EMPEDIA Shield SFTP” (see the FAQ).
* **Bot protection for forms (EMPEDIAcaptcha):** sign-in, registration, password reset, comments, Contact Form 7 and WooCommerce, without cookies and without puzzles for visitors; optional page gate in front of the whole website. It needs a site key and a secret key of the EMPEDIAcaptcha service (free to create).
* **Comments:** switch them off (everywhere, for chosen content types, for old content; reversible, nothing is deleted), delete comments by status and age, and check existing comments with the content check of EMPEDIAcaptcha.

**Optional: connect this site to EMPEDIAcloud**

After you click “Connect”, EMPEDIAcloud evaluates your site: security score with instructions, known vulnerabilities for WordPress, plugins and themes in the exact versions you run (open WPVulnerability database, CC0), PHP support end, a security scan of your public site and a change watcher. One site per organization can be connected in the free tier. Paid plans add availability monitoring with alerts, alerts for file findings, new administrators and backups, sign-in with your EMPEDIAcloud account, backup targets with sign-in (Google Drive, OneDrive, Dropbox, Box, pCloud), EMPEDIAcloud backup storage and more sites. None of the functions listed above is locked behind a connection or a plan.

Updates are delivered by wordpress.org like for any other plugin.

== External services ==

The plugin works on its own and only talks to the services below when you use the matching function.

**1. EMPEDIAcloud (https://empedia.cloud)** – operated by urbanstudio GmbH, Potsdamer Platz 1, 10785 Berlin, Germany. A connection is only made after you click “Connect” or enter a connection code. From then on the plugin sends data to EMPEDIAcloud (once a day, after relevant changes and when you click “Send data now”) and asks it for the status of this site. Terms: https://empedia.cloud/agb.html – Privacy: https://empedia.cloud/datenschutz.html

*What is sent:* the address of this site; the versions of WordPress, PHP and the database; the server software name; the list of installed plugins and themes with name, slug, version, active state and available-update flags; security relevant settings as yes/no values and the number of administrator accounts; which security settings of this plugin are applied; a short summary of the firewall (counters per rule, no visitor data), of the file check (paths and rule codes, never file contents) and of the backup state (schedule, last success, kind of storage target – no access data); changes such as new administrators, installed or updated plugins and themes (type, folder name, version – never user names or e-mail addresses); once an hour a signal that WP-Cron is running.

*What is never sent:* posts, pages, comments, media, visitor data, user names, e-mail addresses or passwords.

To measure how your site responds, the plugin also requests a few addresses of your own site from the server (for example a temporary test file in the uploads folder, which is deleted again immediately, and the public REST users list). The results are sent to EMPEDIAcloud as yes/no values. EMPEDIAcloud also verifies the domain by reading a small proof file that the plugin delivers under `/.well-known/`.

**2. EMPEDIAcaptcha service (the address entered in the settings, normally https://empedia.cloud)** – used when you switch on bot protection. The browser of your visitors loads a small script (`/captcha/v1/widget.js`) from the service and requests a check; your server sends the check token and, if you enable the content check, the text of the submitted comment or message with the e-mail address and IP address of the visitor to the service to verify it. With the page gate switched on, visitors are sent for a short check to the service and come back. The check widget shows the plain text “Protected by EMPEDIAcaptcha” (no link). On eligible sites, `data-badge="false"` on the widget element can hide that notice. Without keys entered, nothing is sent.

**3. Backup targets** – only when you set them up: your own S3-compatible storage, WebDAV or FTP/FTPS server (and an SFTP server with the add-on plugin “EMPEDIA Shield SFTP”); these connections go directly from your site to your server, EMPEDIAcloud is not involved; sign-in based targets Google Drive (Google LLC), OneDrive (Microsoft), Dropbox, Box and pCloud, which store the encrypted backup files in your own account (the sign-in tokens are exchanged through EMPEDIAcloud, the app credentials of the plugin live there); and the optional EMPEDIAcloud backup storage (hosted by BunnyWay d.o.o., Slovenia). Backup files can be encrypted before they leave your server.

**4. wordpress.org** – the file check asks https://api.wordpress.org/core/checksums/1.0/ for the official checksums of your WordPress version and https://downloads.wordpress.org/plugin-checksums/ for those of your plugins (only version and plugin folder name are part of the requests).

**5. WPVulnerability (https://www.wpvulnerability.com, CC0)** – the vulnerability data comes from this open database. It is queried by EMPEDIAcloud, never by the plugin; your site is not named in those requests, only component names and versions.

**6. Sign-in with your EMPEDIAcloud account** (optional, paid plan) – redirects to https://empedia.cloud for the sign-in and back to your site.

== Installation ==

1. Install the plugin from the Plugins screen (or upload it to `/wp-content/plugins/empedia-shield`) and activate it.
2. Open *EMPEDIA Shield* in the admin menu. Protection, sign-in protection, files, firewall, backups, bot protection and comments are tabs there.
3. Optional: click **Connect with EMPEDIAcloud** on the Overview tab and confirm the connection in your account. Agencies can use a connection code (WordPress → Connect a site in EMPEDIAcloud).

The connection to EMPEDIAcloud needs https on your site. If you used the former plugins “EMPEDIAcloud” and “EMPEDIAcaptcha”: deactivate and delete them after activating EMPEDIA Shield; all settings, keys and the connection are kept.

== Frequently Asked Questions ==

= Does the plugin change my site without asking? =

No. Security settings are only applied when you click “Secure now”, and every setting has a “Revert” button. The firewall starts in observe mode.

= Do I need an account? =

No. Security settings, sign-in protection, file check, firewall, backups and comments work without an account. Bot protection needs the keys of the EMPEDIAcaptcha service (free to create), which can also be set up automatically when the site is connected. The cloud evaluation, alerts and availability monitoring need a connection to EMPEDIAcloud.

= Can I back up to an SFTP server? =

Yes, with the separate add-on plugin “EMPEDIA Shield SFTP”. It adds the SFTP (SSH) target to the backup settings of this plugin and brings its own SSH library, which is why it is not part of this plugin. It is not distributed through wordpress.org; you can download it from https://empedia.cloud (WordPress → Download). Saved SFTP targets stay in place when the add-on is not active and work again as soon as it is activated. Developers can register their own storage targets with the filter `empedia_shield_backup_target_types`.

= Do the S3, WebDAV and FTP backup targets need EMPEDIAcloud? =

No. They work on your site alone, without a connection and without a plan. Only the targets that sign in at an online service (Google Drive, OneDrive, Dropbox, Box, pCloud) use EMPEDIAcloud for the sign-in and need a connection and a paid plan.

= What does the “early loader” of the firewall do? =

Optional. If you click “Install early loader” on the Firewall tab, the plugin writes one small file with a fixed content, `wp-content/mu-plugins/empedia-shield-firewall.php`, which only loads the firewall of this plugin before other plugins. The button “Remove early loader” deletes it; it is also removed when you deactivate or delete the plugin. If WordPress cannot write to that folder, nothing is changed and the firewall keeps running as a normal plugin.

= Which files does the plugin write outside its own folder? =

Only on your click: marked blocks in `.htaccess` files for the security settings “no PHP in uploads” and “protect the debug log” (removed when you revert, disconnect, or delete the plugin), the optional must-use file of the firewall, and backups in `wp-content/` (a protected folder). Nothing in `wp-config.php`.

= My web server is nginx. Do the file based settings work? =

The `.htaccess` rules (no PHP in uploads, no public debug log) only work on Apache and compatible servers. On nginx the plugin tells you that the rule was written but has no effect and which rule to add to your server configuration. All other settings work on every server.

= What happens when I deactivate or delete the plugin? =

Deactivating stops the schedules and removes the early loader. Disconnecting reverts all security settings of this plugin. Deleting the plugin ends the connection, removes the marked `.htaccess` blocks, the early loader and every option the plugin stored.

= I locked myself out. What now? =

Add `define( 'EMPEDIA_CLOUD_2FA_OFF', true );` (second factor step off) or `define( 'EMPEDIA_CLOUD_PROTECT_OFF', true );` (whole sign-in protection off) to `wp-config.php`, sign in, and remove the line again. For the bot protection use `define( 'EMPEDIA_CAPTCHA_OFF', true );`, for the firewall `define( 'EMPEDIA_CLOUD_FIREWALL_OFF', true );`. Administrators can also reset the second factor of other users on their profile page.

== Screenshots ==

1. Overview: connect the site with EMPEDIAcloud (optional) and see the security settings at a glance.
2. Security settings with “Secure now” buttons: some applied, some still open, each one reversible.
3. Sign-in protection: two-factor authentication with an authenticator app, passkeys and required roles.
4. File check: WordPress core and plugins compared with the official wordpress.org checksums.
5. Firewall in observe mode: rule groups that only count and sample matches until you let them block.
6. Backups: a saved backup with download, restore and delete, plus storage targets (S3, WebDAV, FTP/FTPS – no account needed) and settings.
7. Bot protection: EMPEDIAcaptcha for sign-in, registration, comments and shop forms, without puzzles.
8. Comments: switch comments off without deleting anything, check and clean up existing comments.

== Changelog ==

= 1.8.6 =
* Fixed: bot protection now validates the WooCommerce Checkout block through the Store API as well as the classic checkout.
* Improved: the CAPTCHA widget script URL uses the new plugin version, so browsers fetch the latest service fix for Contact Form 7.

= 1.8.5 =
* Improved: the check “user names readable via ?author=” no longer tries only ID 1. It also tries up to three real user IDs from the local user table (authors with published posts, then administrators; only numbers are read, no names). One revealed name is enough for “open”.

= 1.8.4 =
* Fixed: the check “user names readable via ?author=1” showed “Unknown” when the site answers 404 (no user with ID 1) or a 307/308 redirect. Both are now judged: nothing is revealed (404) or the redirect target decides.

= 1.8.3 =
* Improved: when a setting is switched on but the site still answers as before, the hint now shows what the last measurement saw (HTTP code, host and cache related headers), so a cache or a different server can be recognised without guessing.

= 1.8.2 =
* Fixed: a security setting that was applied correctly could keep showing as “Action needed” because the check was answered from a page cache, CDN or server cache (the copy stored by the previous measurement). The measurements now use a unique address and no-cache headers, and answers that cannot be judged (redirects, server errors) count as “unknown” instead of a wrong result.
* New: if a setting is switched on but the check still sees the old state, the row explains the likely cause (cache, CDN, other plugin, .htaccess ignored) and offers “Measure again”.

= 1.8.1 =
* Changed: bot protection and the page gate now send all requests to the EMPEDIAcaptcha service through the WordPress HTTP API (wp_remote_request) instead of cURL/PHP streams; proxy and SSL settings of the site apply. The page gate keeps its behaviour (fail-open, host check, signed cookie, search-engine pass, exception paths) and now caches in transients instead of temporary files.
* New: suggested text for the privacy policy of your site (Settings → Privacy → Policy Guide).
* Fixed: escaping, input handling and code-standard findings reported by the Plugin Check.

= 1.8.0 =
* Changed: the plugin is now called EMPEDIA Shield – Security, Firewall & Backups.
* Changed: backup targets S3-compatible storage, WebDAV and FTP/FTPS work without a connection to EMPEDIAcloud and without a paid plan. Only the targets with sign-in at an online service (Google Drive, OneDrive, Dropbox, Box, pCloud) still need the connection and the Pro plan, because they use the sign-in of EMPEDIAcloud.
* Changed: SFTP moved to the separate add-on plugin “EMPEDIA Shield SFTP” (it brings its own SSH library, so this plugin contains no bundled third-party libraries any more). Saved SFTP targets are kept and work again with the add-on.
* New: filter `empedia_shield_backup_target_types` (and `empedia_shield_backup_target_instance`) lets other plugins add backup targets.

= 1.7.0 =
* Renamed to EMPEDIA Shield – Security, Firewall & Backups (formerly “EMPEDIAcloud”). Settings, data and the connection are kept; if the former plugin is still active, EMPEDIA Shield stays off and asks you to deactivate it.
* New: bot protection (EMPEDIAcaptcha) is built in – no separate plugin to install. It works with keys entered by hand, also without a connection to EMPEDIAcloud. A still installed stand-alone EMPEDIAcaptcha plugin is detected and asked to be removed.
* New: the security settings can be used without a connection to EMPEDIAcloud.
* Changed: updates come from wordpress.org; the own update check and installation of plugins from other sources were removed.
* Changed: the optional early start of the firewall (must-use file) is explained next to the button, can be removed with one click and is removed on deactivation and deletion.

= 1.6.1 =
* Improved: the list of saved backups uses proper buttons for download, restore and delete (no typed confirmation field – a confirmation dialog asks before restoring or deleting), and dates and times follow the language of the signed-in person instead of the English site format.

= 1.6.0 =
* New: a short, closable notice on the EMPEDIAcloud page and in the dashboard widget shows which cloud services are part of Pro when a site uses the free tier, and says what to do when a site is paused because all places of the plan are in use. It uses the status that is already stored and causes no additional requests. Security settings, sign-in protection, file check and firewall in the plugin stay free.

= 1.5.0 =
* New: backup status in EMPEDIAcloud: the plugin reports whether backups run (schedule, last success, storage targets, last restore – no access data), and EMPEDIAcloud alerts you when a backup fails or is overdue (Pro, can be switched off per site).

= 1.4.0 =
* New: more storage targets for the encrypted backups (Pro): S3-compatible storage, WebDAV (Nextcloud, ownCloud), FTP/FTPS, SFTP, and sign-in based services Google Drive, OneDrive, Dropbox, Box and pCloud. Several targets can be used at once; restore works from any target.
* New: bot protection tab shows the usage of the plan and points to larger plans when the limit is near.

= 1.3.0 =
* New: backups of files and database on your own server (manual, daily or weekly), optional encryption, download, and restore with an automatic safety copy of the database. Local backups and restore are free; external storage targets follow.

= 1.1.1 =
* Removed in 1.7.0: the own update notice and automatic update installation (updates come from wordpress.org).
* New: the EMPEDIAcaptcha settings are available as a tab; EMPEDIAcloud has its own top-level menu entry and a dashboard widget.

= 1.1.0 =
* New: comments – switch them off (everywhere, for chosen content types, for old content; reversible, nothing is deleted), delete comments by status and age, and check existing comments with the content check of EMPEDIAcaptcha (suspicious ones go to spam).
* New: sign in with your EMPEDIAcloud account (Pro): members of your organization or agency can use the EMPEDIAcloud sign-in, including passkeys; only for users that already exist on the site with the same verified e-mail address.
* New: firewall – checks requests for SQL injection, script injection, file inclusion, PHP uploads, attack tools, probing, XML-RPC abuse and too many requests. Starts in observe mode (nothing is blocked), blocking only after 72 hours, emergency switch in EMPEDIAcloud, optional early loader.
* New: sign-in protection – limits for failed attempts, two-factor authentication (authenticator app, recovery codes), passkeys, second factor required for roles.
* New: file integrity check against the official checksums, PHP in uploads, backdoor patterns (hints only); expected items can be marked.
* New: change watcher – new administrators, plugins, themes, WordPress updates, backups.
* New: one-click bot protection for forms (EMPEDIAcaptcha).
* Security check: new items “sign-in limit” and “administrators without second factor”.

= 1.0.0 =
* First release: connect with EMPEDIAcloud, inventory, security check with reversible settings, vulnerabilities, availability monitoring (Pro), security scan.

== Upgrade Notice ==

= 1.8.2 =
Fixes security settings that stayed marked as open behind a page cache or CDN; adds “Measure again”.

= 1.8.1 =
Technical clean-up (WordPress HTTP API for bot protection and page gate); no action needed.

= 1.8.0 =
SFTP backup targets now need the add-on plugin “EMPEDIA Shield SFTP”; saved targets are kept. S3, WebDAV and FTP targets no longer need a connection to EMPEDIAcloud.

= 1.7.0 =
EMPEDIAcloud is now EMPEDIA Shield and includes the bot protection. Deactivate and delete the former plugins “EMPEDIAcloud” and “EMPEDIAcaptcha” after activating it; your settings are kept.

= 1.1.0 =
Adds sign-in protection (two-factor, passkeys), a file integrity check and a change watcher. Review Sign-in protection after the update.

= 1.0.0 =
First release.
