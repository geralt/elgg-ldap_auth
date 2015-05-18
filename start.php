<?php
/**
 * Elgg LDAP authentication
 *
 * @package ElggLDAPAuth
 * @license http://www.gnu.org/licenses/old-licenses/gpl-2.0.html GNU Public License version 2
 * @author Misja Hoebe <misja.hoebe@gmail.com>
 * @link http://community.elgg.org/profile/misja
 */

// Register the initialization function
elgg_register_event_handler('init', 'system', 'ldap_auth_init');

/**
 * LDAP Authentication init
 */
function ldap_auth_init() {
	// Register the authentication handler
	register_pam_handler('ldap_auth_authenticate');

    elgg_unregister_plugin_hook_handler('usersettings:save', 'user', '_elgg_set_user_password');
    // Deregister default action for password changing
    elgg_unregister_action('usersettings/save');
    // Register own password changing action
    elgg_register_action('usersettings/save', dirname(__FILE__) . "/actions/save.php");
}

/**
 * Get an instance of the LdapServer class
 *
 * @return
 */
function ldap_auth_get_server() {
	$settings = elgg_get_plugin_from_id('ldap_auth');

	static $server;

	if (!$server) {
		try {
			$server = new LdapServer($settings);
		} catch (Exception $e) {
			elgg_log($e->getMessage());

			return false;
		}
	}

	return $server;
}

/**
 * Authenticate user against the credential
 *
 * @param array $credentials
 * @return boolean
 */
function ldap_auth_authenticate($credentials) {
    
	$settings = elgg_get_plugin_from_id('ldap_auth');
	$server = ldap_auth_get_server();
	if (!$server) {
		// Unable to connect to LDAP server
		register_error(elgg_echo('ldap_auth:connection_error'));
		return false;
	}

	$settings = elgg_get_plugin_from_id('ldap_auth');

	$username = elgg_extract('username', $credentials);
	$password = elgg_extract('password', $credentials);

	$filter = "({$settings->filter_attr}={$username})";

	if (!$server->bind()) {
		register_error(elgg_echo('ldap_auth:connection_error'));
		return false;
	}

	$result = $server->search($filter);

	if (empty($result)) {
		// User was not found
		return false;
	}

	// Bind using user's distinguished name and password
	$success = $server->bind($result['dn'], $password);

	if (!$success) {
		// dn/password combination doesn't exist
		return false;
	}

	// Check if the user is a member of the group, in case both parameters are filled
	
	$result2 = $server->isMember($result['dn']);
	
	if (!$result2) {
		elgg_log("User found in directory and its bind completed ok, but is not a member of the required group","NOTICE");
		register_error(elgg_echo('ldap_auth:not_in_group'));
		return false;
	}

	$user = get_user_by_username($username);

	if ($user) {
		return login($user);
	}

	if ($settings->create_user !== 'off') {
		return ldap_auth_create_user($username, $result);
	}

	register_error(elgg_echo("ldap_auth:no_account"));
	return false;
}

/**
 * Create a new user from the data provided by LDAP
 *
 * @param string $username
 * @param string $password
 * @param array  $data Data fetched from LDAP
 */
function ldap_auth_create_user($username, $data) {
	// Check that we have the values. register_user() will take
	// care of more detailed validation.
	$firstname = elgg_extract('firstname', $data);
	$lastname  = elgg_extract('lastname', $data);
	$email     = elgg_extract('mail', $data);
	$password  = substr(str_shuffle(str_repeat('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', mt_rand(1,10))),1,20);

	// Combine firstname and lastname
	$name = implode(' ', array($firstname, $lastname));
 
	try {
		$guid = register_user($username, $password, $name, $email);
	} catch (Exception $e) {
		register_error($e->getMessage());
		return false;
	}

	if (!$guid) {
		register_error(elgg_echo('ldap_auth:no_register'));
		elgg_log("Failed to create an account for LDAP user $username");
		return false;
	}

	$user = get_entity($guid);

	// Allow plugins to respond to the registration
	$params = array(
		'user' => $user,
		'ldap_entry' => $data,
	);

	if (!elgg_trigger_plugin_hook('register', 'user', $params, true)) {
		// For some reason one of the plugins returned false.
		// This most likely means that something went wrong
		// and we will have to remove the user.
		$user->delete();

		register_error(elgg_echo('registerbad'));

		return false;
	}

	// Validate the user
	elgg_set_user_validation_status($guid, true, 'LDAP plugin based validation');

	return true;
}

/**
 * Change LDAP user's password
 *
 * @param string $user user name
 * @param string $oldPassword old password
 * @param string $newPassword new password
 * @param string $newPasswordCnf new password
 * @return bool status of change
 */
function ldap_auth_change_password( $user, $oldPassword, $newPassword, $newPasswordCnf ) {
    
    $settings = elgg_get_plugin_from_id('ldap_auth');
    $server = ldap_auth_get_server();
    
    ldap_connect($server);
    $con = ldap_connect($server->hostname, $server->port);
    ldap_set_option($con, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    // bind anon and find user by uid
    $user_search = ldap_search($con, $server->basedn, "(uid=$user)");
    
    $user_get = ldap_get_entries($con, $user_search);
    $user_entry = ldap_first_entry($con, $user_search);
    $user_dn = ldap_get_dn($con, $user_entry);
   
    /* Start the testing */
    if (ldap_bind($con, $user_dn, $oldPassword) === false) {
        register_error(elgg_echo('ldap_auth:password:change:binderror'));
        return false;
    }

    if ($newPassword != $newPasswordCnf ) {
        register_error(elgg_echo('ldap_auth:password:change:newnotmatch'));
        return false;
    }

    if ($newPassword == $oldPassword ) {
        register_error(elgg_echo('ldap_auth:password:change:samepass'));
        return false;
    }

    if (strlen($newPassword) < 8 ) {
        register_error(elgg_echo('ldap_auth:password:change:passlenght'));
        return false;
    }
    if (!preg_match("/[0-9]/",$newPassword)) {
        register_error(elgg_echo('ldap_auth:password:change:nonumber'));
        return false;
    }
    if (!preg_match("/[a-zA-Z]/",$newPassword)) {
        register_error(elgg_echo('ldap_auth:password:change:noletter'));
        return false;
    }
    if (!preg_match("/[A-Z]/",$newPassword)) {
        register_error(elgg_echo('ldap_auth:password:change:noupper'));
        return false;
    }
    if (!preg_match("/[a-z]/",$newPassword)) {
        register_error(elgg_echo('ldap_auth:password:change:nolower'));
        return false;
    }
    if (!$user_get) {
        register_error(elgg_echo('ldap_auth:password:change:conerror'));
        return false;
    }
    
    /* And Finally, Change the password */
    $entry = array();
    $entry["userPassword"] = "{SHA}" . base64_encode( pack( "H*", sha1( $newPassword ) ) );
   
    if (ldap_modify($con,$user_dn,$entry) === false){
        $error = ldap_error($con);
        $errno = ldap_errno($con);
        register_error(elgg_echo('ldap_auth:password:change:error'));
        return false;
    } else {
        system_message(elgg_echo('ldap_auth:password:change:success'));
        return true;
  }
}
