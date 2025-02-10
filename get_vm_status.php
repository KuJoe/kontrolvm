<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

define('AmAllowed', TRUE);
require_once('functions.php');

$vmname = $_POST['vmname'];
$ipaddr = $_POST['nodeip'];
$sshport = $_POST['nodeport'];
$sshuser = $_POST['nodeuser'];
$sshkey = $_POST['nodepw'];

$state = getVMState($vmname,$ipaddr,$sshport,$sshuser,$sshkey);
echo $state;

?>