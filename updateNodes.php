<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

if(!defined('AmAllowed')) {
	die('Error 001A');
}
require_once('functions.php');
$servers = getServerList('1');

if (count($servers) > 0) {
	foreach ($servers as $server) {
		$node_id = $server['node_id'];
		$ipaddr = $server['ipaddr'];
		$sshport = $server['sshport'];
		$sshuser = $server['sshuser'];
		$sshkey = $server['sshkey'];
		getNodeInfo($node_id, $ipaddr, $sshport, $sshuser, $sshkey);
		getNodeStats($node_id, $ipaddr, $sshport, $sshuser, $sshkey);
	}
} else {
	return false;
}

return true;

?>