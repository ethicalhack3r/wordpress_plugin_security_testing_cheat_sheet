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

The following functions can cause XSS if not secured as they use the PHP_SELF variable:

- ```add_query_arg()```
- ```remove_query_arg()```

References:

[https://blog.sucuri.net/2015/04/security-advisory-xss-vulnerability-affecting-multiple-wordpress-plugins.html](https://blog.sucuri.net/2015/04/security-advisory-xss-vulnerability-affecting-multiple-wordpress-plugins.html)
[https://make.wordpress.org/plugins/2015/04/20/fixing-add_query_arg-and-remove_query_arg-usage/](https://make.wordpress.org/plugins/2015/04/20/fixing-add_query_arg-and-remove_query_arg-usage/)
[https://developer.wordpress.org/reference/functions/add_query_arg/](https://developer.wordpress.org/reference/functions/add_query_arg/)
[https://developer.wordpress.org/reference/functions/remove_query_arg/](https://developer.wordpress.org/reference/functions/remove_query_arg/)

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

## File Download

- ```file()```
- ```readfile()```
- ```file_get_contents()```

## File Inclusion

- ```include()```
- ```require()```
- ```include_once()```
- ```require_once()```
- ```fread()```

## File Manipulation

- ```unlink()``` delete arbitrary files

## PHP Object Injection

- ``` unserialize()``` any raw user input passed to this function is probably exploitable, if serialized() first, probably not vulnerable

### PHP Object Injection Tips

Use this [simple Burp Suite extention](https://gist.github.com/ethicalhack3r/7c2618e5fffd564e2734e281c86a2c9b) along with the [PHP Object Injection WordPress Plugin](https://www.pluginvulnerabilities.com/2017/07/24/wordpress-plugin-for-use-in-testing-for-php-object-injection/) created by White Fir Design.

## Command Execution

- ```system()```
- ```exec()```
- ```passthru()```
- ```shell_exec()```

## PHP Code Execution

- ```eval()```
- ```assert()```
- ```preg_replace()``` dangerous "e" flag deprecated since PHP >= 5.5.0 and removed in PHP >= 7.0.0.

## Authorisation

- ```is_admin()``` does not check if the user is authenticated as administrator, only checks if page displayed is in the admin section, can lead to auth bypass if misused.
- ```is_user_admin()``` same as above
- ```current_user_can()``` used for checking authorisation. This is what should be used to check authorisation.
- ```add_action( 'wp_ajax_nopriv_``` permits non-authenticated users to use the AJAX function (https://codex.wordpress.org/Plugin_API/Action_Reference/wp_ajax_(action)).

## Open Redirect

- ```wp_redirect()``` function can be used to redirect to user supplied URLs. If user input is not sanitised or validated this could lead to Open Redirect vulnerabilities.

## Cross-Site Request Forgery (CSRF)

- ```wp_nonce_field()``` adds CSRF token to forms
- ```wp_nonce_url()``` adds CSRF token to URL
- ```wp_verify_nonce()``` checks the CSRF token validity server side
- ```check_admin_referer()``` checks the CSRF token validity server side and came from admin screen

## SSL/TLS

- ```CURLOPT_SSL_VERIFYHOST``` if set to 0 then does not check name in host certificate
- ```CURLOPT_SSL_VERIFYPEER``` if set to FALSE then does not check if the certificate (inc chain), is trusted. A Man-in-the-Middle (MitM) attacker could use a self-signed certificate.
- Check if HTTP is used to communicate with backend servers or APIs. A grep for "http://" should be sufficient.

## Priviledge Escalation

- ```update_option()``` if user input is sent unvalidated, it could allow an attacker to update arbitrary WordPress options.
- ```do_action()``` if user input is sent unvalidated, it could allow an attacker to update arbitrary WordPress actions.

See: https://www.wordfence.com/blog/2018/11/privilege-escalation-flaw-in-wp-gdpr-compliance-plugin-exploited-in-the-wild/

## Automated Static Code Analysis

- ```WordPress-Coding-Standards``` contains some security rules. 

Example:

```
./vendor/bin/phpcs --standard=WordPress --sniffs=WordPress.CSRF.NonceVerification,WordPress.DB.PreparedSQL,WordPress.DB.PreparedSQLPlaceholders,WordPress.DB.RestrictedClasses,WordPress.DB.RestrictedFunctions,WordPress.Security.NonceVerification,WordPress.Security.PluginMenuSlug,WordPress.Security.SafeRedirect,WordPress.Security.ValidatedSanitizedInput,WordPress.Security.EscapeOutputSniff,WordPress.WP.PreparedSQL,WordPress.XSS.EscapeOutput -p -d memory_limit=256M --colors /path/to/plugin/
```

See: https://github.com/WordPress-Coding-Standards/WordPress-Coding-Standards

## Further reading/references:

1. [https://developer.wordpress.org/plugins/security/](https://developer.wordpress.org/plugins/security/)
2. [https://make.wordpress.org/plugins/2013/11/24/how-to-fix-the-intentionally-vulnerable-plugin/](https://make.wordpress.org/plugins/2013/11/24/how-to-fix-the-intentionally-vulnerable-plugin/)
3. [http://wordpress.tv/2011/01/29/mark-jaquith-theme-plugin-security/](http://wordpress.tv/2011/01/29/mark-jaquith-theme-plugin-security/)
4. [https://www.wordfence.com/learn/](https://www.wordfence.com/learn/)
5. https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html
6. https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html
7. https://www.owasp.org/index.php/OWASP_Wordpress_Security_Implementation_Guideline
8. http://php.net/manual/en/function.preg-replace.php
