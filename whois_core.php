<?php
/**
 * whois_core.php — Super Whois v2.2.2 shared library (entry point)
 *
 * Loads modular components from lib/. No functions defined here.
 * index.php and api.php require this file as before — no changes needed.
 *
 * Module dependency order matters; the actual load order below is canonical.
 */

require_once __DIR__ . '/config.php';

$libDir = __DIR__ . '/lib';

// network → log → cache → auth/PSL/parse → rdap → whois → dns → utils
require_once $libDir . '/network.php';
require_once $libDir . '/log.php';
require_once $libDir . '/cache.php';
require_once $libDir . '/auth.php';
require_once $libDir . '/public_suffix.php';
require_once $libDir . '/parse.php';
require_once $libDir . '/rdap.php';
require_once $libDir . '/whois.php';
require_once $libDir . '/dns.php';
require_once $libDir . '/utils.php';
