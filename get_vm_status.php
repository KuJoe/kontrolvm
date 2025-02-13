<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

define('AmAllowed', TRUE);
require_once('functions.php');

$vmname = $_POST['vmname'];
$node_id = $_POST['node_id'];

$state = getVMState($vmname,$node_id);
echo $state;

?>