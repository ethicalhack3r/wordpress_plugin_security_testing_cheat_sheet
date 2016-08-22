# WordPress Plugin Security Testing Cheat Sheet

This cheat sheet was compiled by [Dewhurst Security](https://dewhurstsecurity.com "Dewhurst Security") to record the knowledge gained when testing WordPress plugins for security issues for our clients. The security documentation provided by WordPress and found online for plugin security is sparse, outdated or unclear. This cheat sheet is intended for Penetration Testers who audit WordPress plugins or developers who wish to audit their own WordPress plugins.

This is a living document, feedback in the form of Issues or Pull Requests is very much welcomed.

## Cross-Site Scripting (XSS)

Check if the following global PHP variables are echo'd to pages, or stored in the database and echo'd at a later time without first being sanitised or output encoded.

- ```$_GET```
- ```$_POST```
- ```$_REQUEST```
- ```$_SERVER['REQUEST_URI']```
- ```$_SERVER['PHP_SELF']```
- ```$_SERVER['HTTP_REFERER']```
- ```$_COOKIE```

_(Note: the list of sources above is not extensive nor complete)_

### Cross-Site Scripting (XSS) Tips

#### Unsafe API functions

The following functions can cause XSS if not secured:

- ```add_query_arg()```
- ```remove_query_arg()```

Reference: [https://blog.sucuri.net/2015/04/security-advisory-xss-vulnerability-affecting-multiple-wordpress-plugins.html](https://blog.sucuri.net/2015/04/security-advisory-xss-vulnerability-affecting-multiple-wordpress-plugins.html)

#### DISALLOW_UNFILTERED_HTML

When doing dynamic testing for XSS the following setting in the wp-config.php file may reduce false positive results as it prevents administrative and editor users from being able to embed/execute JavaScript/HTML, which by default they are permitted to do.

```
define( 'DISALLOW_UNFILTERED_HTML', true );
``` 

## SQL Injection

Unsafe API methods (require sanitising/escaping):

- ```$wpdb->query()```
- ```$wpdb->get_var()```
- ```$wpdb->get_row()```
- ```$wpdb->get_col()```
- ```$wpdb->get_results()```
- ```$wpdb->replace()```

Safe API methods (according to WordPress):

- ```$wpdb->insert()```
- ```$wpdb->update()```
- ```$wpdb->delete()```

Safe code, prepared statement:

``` <?php $sql = $wpdb->prepare( 'query' , value_parameter[, value_parameter ... ] ); ?> ```

Note: Before WordPress 3.5 ```$wpdb->prepare``` could be used insecurely as you could just pass the query without using placeholders, like in the following example:

```$wpdb->query( $wpdb->prepare( "INSERT INTO table (user, pass) VALUES ('$user', '$pass')" ) );```

### SQL Injection Tips

Unsafe escaping ('securing') API methods:

- ```esc_sql()``` function does not adequately protect against SQL Injection [https://codex.wordpress.org/Function_Reference/esc_sql](https://codex.wordpress.org/Function_Reference/esc_sql)
- ```escape()``` same as above
- ```esc_like()``` same as above
- ```like_escape()``` same as above

#### Displaying/hiding SQL errors:

```
<?php $wpdb->show_errors(); ?> 
<?php $wpdb->hide_errors(); ?> 
<?php $wpdb->print_error(); ?>
```

## Authorisation

- ```is_admin()``` does not check if the user is authenticated as administrator, only checks if page displayed is in the admin section, can lead to auth bypass if misused.
- ```is_user_admin()``` same as above
- ```current_user_can()``` used for checking authorisation. This is what should be used to check authorisation.

## Open Redirect

- ```wp_redirect()``` function can be used to redirect to user supplied URLs. If user input is not sanitised or validated this could lead to Open Redirect vulnerabilities.

## Cross-Site Request Forgery (CSRF)

- ```wp_nonce_field()``` adds CSRF token to forms
- ```wp_nonce_url()``` adds CSRF token to URL
- ```wp_verify_nonce()``` checks the CSRF token validity server side
- ```check_admin_referer()``` checks the CSRF token validity server side and came from admin screen

## Further reading/references:

1. [https://developer.wordpress.org/plugins/security/](https://developer.wordpress.org/plugins/security/)
2. [https://make.wordpress.org/plugins/2013/11/24/how-to-fix-the-intentionally-vulnerable-plugin/](https://make.wordpress.org/plugins/2013/11/24/how-to-fix-the-intentionally-vulnerable-plugin/)
3. [http://wordpress.tv/2011/01/29/mark-jaquith-theme-plugin-security/](http://wordpress.tv/2011/01/29/mark-jaquith-theme-plugin-security/)
4. [https://www.wordfence.com/learn/](https://www.wordfence.com/learn/)
