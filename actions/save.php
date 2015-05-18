<?php
/**
 * Action to reset a password when already validated.
 *
 * @package Elgg
 * @subpackage Core
 */

$user = elgg_get_logged_in_user_entity();
if ( $user != null) {
    ldap_auth_change_password( $user->username, get_input('current_password'), get_input('password'), get_input('password2'));
}
forward(REFERRER);

