<?php

/**
 * Plugin Name: WP IdleKick
 * Description: Automatically logs out any logged-in user after 1 hour of inactivity based on WordPress activity.
 * Version: 1.0
 * Author: Angelo
 * License: GPL2
 */

require 'puc/plugin-update-checker.php';

use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

$myUpdateChecker = PucFactory::buildUpdateChecker(
    'http://206.189.194.86/api/license/verify', // Your licensing system API endpoint
    __FILE__,
    'wp-idlekick'
);

// Append required query args (license_key, plugin_slug, domain) on update checks.
$myUpdateChecker->addQueryArgFilter(function (array $queryArgs) {
    $license_key           = get_option('wp_idlekick_license_key', '');
    $queryArgs['license_key'] = $license_key;
    $queryArgs['plugin_slug'] = 'wp-idlekick';
    $queryArgs['domain']      = home_url();
    return $queryArgs;
});

defined('ABSPATH') || exit;

/* =============================================================================
   LICENSE VALIDATION AND ADMIN INTERFACE
   ============================================================================= */

/**
 * Check whether the stored license key is valid.
 * Uses caching (via transients) for one hour to minimize API calls.
 *
 * @return bool True if valid; false otherwise.
 */
function wpidlekick_is_license_valid()
{
    $cached = get_transient('wpidlekick_license_valid');
    if (false !== $cached) {
        return $cached;
    }
    $license_key = get_option('wp_idlekick_license_key', '');
    if (empty($license_key)) {
        set_transient('wpidlekick_license_valid', false, HOUR_IN_SECONDS);
        return false;
    }
    $response = wp_remote_post('http://206.189.194.86/api/license/verify', [
        'timeout' => 15,
        'body'    => [
            'license_key' => $license_key,
            'plugin_slug' => 'wp-idlekick',
            'domain'      => home_url(),
        ],
    ]);
    if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
        set_transient('wpidlekick_license_valid', false, HOUR_IN_SECONDS);
        return false;
    }
    $license_data = json_decode(wp_remote_retrieve_body($response), true);
    // Change is here—using filter_var to accept string "true" or boolean true.
    $valid = (!empty($license_data) && filter_var($license_data['valid'], FILTER_VALIDATE_BOOLEAN));
    set_transient('wpidlekick_license_valid', $valid, HOUR_IN_SECONDS);
    return $valid;
}


/**
 * Display an admin notice if the plugin does not have a valid license.
 */
function wpidlekick_admin_license_check()
{
    if (! is_admin()) {
        return;
    }
    if (empty(get_option('wp_idlekick_license_key'))) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-error"><p>' .
                __('WP IdleKick is disabled because it does not have a valid license. Please enter a valid license key.', 'wp-idlekick') .
                '</p></div>';
        });
    }
}
add_action('admin_init', 'wpidlekick_admin_license_check');

/**
 * Add a License Settings page under the Settings menu.
 */
function wpidlekick_add_license_settings_page()
{
    add_options_page(
        'WP IdleKick License Settings',
        'IdleKick License',
        'manage_options',
        'wpidlekick-license-settings',
        'wpidlekick_render_license_settings_page'
    );
}
add_action('admin_menu', 'wpidlekick_add_license_settings_page');

/**
 * Render the License Settings page.
 * Provides forms to update or remove the license key.
 */
function wpidlekick_render_license_settings_page()
{
    if (! current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.', 'wp-idlekick'));
    }

    // Process form submission for updating the license.
    if (isset($_POST['update_license'])) {
        check_admin_referer('wpidlekick_license_settings');
        $new_key = sanitize_text_field($_POST['wpidlekick_license_key']);
        $response = wp_remote_post('http://206.189.194.86/api/license/validate', [
            'body'    => [
                'license_key' => $new_key,
                'plugin_slug' => 'wp-idlekick',
                'domain'      => home_url(),
            ],
            'timeout' => 15,
        ]);
        if (is_wp_error($response)) {
            echo '<div class="error"><p>' . __('There was an error contacting the licensing server. Please try again later.', 'wp-idlekick') . '</p></div>';
        } else {
            $status_code = wp_remote_retrieve_response_code($response);
            if ($status_code == 200) {
                update_option('wp_idlekick_license_key', $new_key);
                delete_transient('wpidlekick_license_valid');
                echo '<div class="updated"><p>' . __('License key updated successfully.', 'wp-idlekick') . '</p></div>';
            } elseif ($status_code == 404) {
                echo '<div class="error"><p>' . __('License key is invalid. Please enter a valid license key.', 'wp-idlekick') . '</p></div>';
            } elseif ($status_code == 403) {
                echo '<div class="error"><p>' . __('License key is inactive or the activation limit has been reached.', 'wp-idlekick') . '</p></div>';
            } else {
                echo '<div class="error"><p>' . __('Unexpected response from licensing server.', 'wp-idlekick') . '</p></div>';
            }
        }
    }

    // Process form submission for removing the license.
    if (isset($_POST['remove_license'])) {
        check_admin_referer('wpidlekick_license_settings');
        $current_key = get_option('wp_idlekick_license_key', '');
        if (! empty($current_key)) {
            $response = wp_remote_post('http://206.189.194.86/api/license/deactivate', [
                'body'    => [
                    'license_key' => $current_key,
                    'plugin_slug' => 'wp-idlekick',
                    'domain'      => home_url(),
                ],
                'timeout' => 15,
            ]);
            if (! is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200) {
                delete_option('wp_idlekick_license_key');
                delete_transient('wpidlekick_license_valid');
                echo '<div class="updated"><p>' . __('License removed successfully. WP IdleKick is now disabled until a valid license key is entered.', 'wp-idlekick') . '</p></div>';
            } else {
                echo '<div class="error"><p>' . __('There was an error removing the license. Please try again.', 'wp-idlekick') . '</p></div>';
            }
        }
    }

    $current_key = esc_attr(get_option('wp_idlekick_license_key', ''));
?>
    <div class="wrap">
        <h1><?php _e('WP IdleKick License Settings', 'wp-idlekick'); ?></h1>
        <form method="post" action="">
            <?php wp_nonce_field('wpidlekick_license_settings'); ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row"><?php _e('License Key', 'wp-idlekick'); ?></th>
                    <td>
                        <input type="text" name="wpidlekick_license_key" value="<?php echo $current_key; ?>" style="width: 400px;" />
                        <p class="description"><?php _e('Enter your valid license key for WP IdleKick.', 'wp-idlekick'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button('Update License', 'primary', 'update_license'); ?>
            <?php if (! empty($current_key)) : ?>
                <?php submit_button('Remove License', 'secondary', 'remove_license'); ?>
            <?php endif; ?>
        </form>
    </div>
<?php
}

/* =============================================================================
   PLUGIN FUNCTIONALITY CONDITIONAL ON A VALID LICENSE
   ============================================================================= */

/**
 * Initialize WP IdleKick only if a valid license key is present.
 */
function wpidlekick_init()
{
    if (! wpidlekick_is_license_valid()) {
        return;
    }
    add_action('init', 'wpidlekick_track_activity');
    add_action('init', 'wpidlekick_check_for_inactivity', 20);
}
add_action('plugins_loaded', 'wpidlekick_init');

/**
 * Update the user's last activity time on every request.
 */
function wpidlekick_track_activity()
{
    if (is_user_logged_in()) {
        update_user_meta(get_current_user_id(), '_wpidlekick_last_activity', time());
    }
}

/**
 * Check for inactivity and log out the user if they’ve been idle too long.
 */
function wpidlekick_check_for_inactivity()
{
    if (! is_user_logged_in()) {
        return;
    }
    $user_id      = get_current_user_id();
    $last_activity = get_user_meta($user_id, '_wpidlekick_last_activity', true);
    $timeout      = 3600; // 1 hour in seconds
    if ($last_activity && (time() - $last_activity) > $timeout) {
        wp_logout();
        wp_redirect(wp_login_url());
        exit;
    }
}

/* =============================================================================
   CLEANUP ON DEACTIVATION
   ============================================================================= */

/**
 * On plugin deactivation, hit the licensing API to deactivate the license,
 * then clear the stored license key and validation cache.
 */
function wpidlekick_on_deactivation()
{
    $license_key = get_option('wp_idlekick_license_key', '');
    if (! empty($license_key)) {
        wp_remote_post('http://206.189.194.86/api/license/deactivate', [
            'body'    => [
                'license_key' => $license_key,
                'plugin_slug' => 'wp-idlekick',
                'domain'      => home_url(),
            ],
            'timeout' => 15,
        ]);
    }
    delete_option('wp_idlekick_license_key');
    delete_transient('wpidlekick_license_valid');
}
register_deactivation_hook(__FILE__, 'wpidlekick_on_deactivation');
