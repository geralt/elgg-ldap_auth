# elgg-ldap_auth
LDAP authentication for Elgg

Forked to further enhance the integration with LDAP

Current goals achieved:
- added optional groupOfNames membership requirement (users are in a OU, but only members of a certain groupOfNames can login)
- complicated random password set when creating user in elgg, not the same given in auth.

Goals left
- Password change form in user settings change LDAP password, not the one in the internal DB
