<?php

// $Id$

$request_time = microtime( true );

require_once "grab_globals.inc.php";
require_once "systemdefaults.inc.php";
require_once "areadefaults.inc.php";
require_once "config.inc.php";
require_once "language.inc";
require_once "internalconfig.inc.php";
require_once "theme.inc";
require_once "functions.inc";
require_once "dbsys.inc";
require_once "mrbs_auth.inc";
require_once "standard_vars.inc.php";

if( $firephp ) {
	ob_start();
	require_once "FirePHPCore/fb.php";
}

?>
