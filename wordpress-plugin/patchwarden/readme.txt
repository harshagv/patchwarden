=== Patchwarden ===
Contributors: patchwarden
Tags: security, php, updates, monitoring
Requires at least: 6.0
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPLv2 or later

Tells Patchwarden which PHP version and plugins your site runs, and runs the plugin updates you approve. No password is ever shared.

== Installation ==

1. In your Patchwarden dashboard, open your site and download the plugin.
2. In WordPress: Plugins > Add New > Upload Plugin, choose patchwarden.zip, Install, Activate.
3. In your Patchwarden dashboard, press "Get your plugin key" and copy it.
4. In WordPress: Settings > Patchwarden, paste the key, press "Save and connect". Done.

== What it sends ==

Your PHP version, WordPress version, and the names and versions of your plugins and themes. Nothing else: no users, no posts, no settings.

== What it can do ==

Only what you approve in the Patchwarden dashboard: update a plugin or theme to its latest version from WordPress.org. It cannot change your PHP version, and Patchwarden never connects into your site: the plugin checks in for approved work.

== Removing it ==

Deleting the plugin removes its settings and schedule, and tells Patchwarden to switch off its key.
