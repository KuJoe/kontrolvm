<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

define('AmAllowed', TRUE);
require_once('functions.php');

$vmname = trim($_POST['vmname']);
$node_id = (int)$_POST['node_id'];

$state = getVMState($vmname,$node_id);
if($state == 'running') {
	echo "running";
} else {
	echo "offline";
}

?>