<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

if(!defined('AmAllowed')) {
	die('Error 001A');
}
require_once('functions.php');
$servers = getServerList('1');

if(count($servers) > 0) {
	foreach ($servers as $server) {
		if(getNodeInfo($server['node_id'])) {
			getNodeStats($server['node_id']);
		}
	}
	updateLastRunTime('updateNodes.php');
} else {
	return false;
}

return true;

?>