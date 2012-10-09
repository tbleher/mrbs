<?php

/* $Id$
 *
 * Authentication scheme that uses IMAP as the source for user
 * authentication. It requires you to have the PHP 'imap' extension
 * installed and enabled.
 *
 * To use this authentication scheme set the following
 * things in config.inc.php:
 *
 * $auth["realm"] = "MRBS";    // Or any other string
 * $auth["type"]  = "imap_php";
 *
 * You must also configure at least:
 *
 * $auth["imap_php"]["hostname"] = "mailserver.hostname";
 *
 * You can also specify any of the following options:
 *
 * // Specifies the port number to connect to
 * $auth["imap_php"]["port"] = 993;
 *
 * // Use SSL
 * $auth["imap_php"]["ssl"] = TRUE;
 *
 * // Use TLS
 * $auth["imap_php"]["tls"] = TRUE;
 *
 * // Turn off SSL/TLS certificate validation
 * $auth["imap_php"]["novalidate-cert"] = TRUE;
 *
 * Then, you may configure admin users:
 *
 * $auth["admin"][] = "imapuser1";
 * $auth["admin"][] = "imapuser2";
 */

function authValidateUser($user, $pass)
{
  global $auth;

# erlaube auch die Konfiguration von Usern ueber die Config-Datei
  if ((isset($auth["user"][$user]) &&
       ($auth["user"][$user] == $pass)
        ) ||
      (isset($auth["user"][strtolower($user)]) &&
       ($auth["user"][strtolower($user)] == $pass)
        ))
  {
    return 1; // User validated
  }
    
  $ret = 0;

  $location = "{".$auth["imap_php"]["hostname"];

  if (isset($auth["imap_php"]["port"]))
  {
    $location .= ":".$auth["imap_php"]["port"];
  }

  $location .= "/imap";

  if ($auth["imap_php"]["ssl"])
  {
    $location .= "/ssl";
  }

  if ($auth["imap_php"]["tls"])
  {
    $location .= "/tls";
  }

  if ($auth["imap_php"]["novalidate-cert"])
  {
    $location .= "/novalidate-cert";
  }

  $location .= "}INBOX";

  // Hinzugefuegt von Thomas Bleher, 2010-10-20
  // im CVJM gibt es das Namensschema vorname.nachname für Email-Adressen; zum Anmelden am IMAP-Server musss man aber vnachname verwenden.
  // Allerdings gibt es auch ein paar Sonderaccounts, die nicht verändert werden dürfen
  $orig_user = $user;
  $user = preg_replace('/^([a-z])[a-z]+\\.([a-z]+)$/', '$1$2', $user, -1, $count);
  // Benutzer-Name entspricht nicht dem vorgegebenen Schema, also vorname.nachname oder einer der Ausnahmen unten
  if( $orig_user == $user && $user != 'JMH' && $user != 'juze-buero' && $user != 'kiju-buero' && $user != 'cv_info' && $user != 'jungeleute' )
    return 0;

  $mbox = imap_open($location, $user, $pass);

  if ($mbox != FALSE)
  {
    imap_close($mbox);
    $ret = 1;
  }
  return $ret;
}

/* authGetUserLevel($user)
 *
 * Determines the users access level
 *
 * $user - The user name
 *
 * Returns:
 *   The users access level
 */
function authGetUserLevel($user)
{
  global $auth;
  $admins = $auth['admin'];
  // User not logged in, user level '0'
  if(!isset($user))
  {
    return 0;
  }

  // Check if the user is can modify
  for ($i = 0; $admins[$i]; $i++)
  {
    if(strcasecmp($user, $admins[$i]) == 0)
    {
      return 2;
    }
  }

  // Everybody else is access level '1'
  return 1;
}

?>
