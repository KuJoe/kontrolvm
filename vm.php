<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php");
	exit; 
} else {
	define('AmAllowed', TRUE);
	require_once('config.php');
	require_once('functions.php');
	$loggedin_id = (int)$_SESSION['staff_id'];
	$myrole = (int)$_SESSION["staff_role"];
	$chkActive = checkActive($loggedin_id);
	$chkLocked = checkLockedOut($loggedin_id);
	if($chkLocked == true OR $chkActive == false) {
		header("Location: logout.php");
		exit;
	}
	$chkRole = getStaffRole($loggedin_id);
	$allowedRoles = ['1', '2', '3', '9'];
	if (!in_array($chkRole, $allowedRoles)) {
		header("Location: home.php?s=99");
		exit;
	}
	if (isset($_GET['id'])) {
		if (isset($_GET['s'])) {
			if ($_GET['s'] == '1') {
				$success = "VM updated successfully.";
			} elseif ($_GET['s'] == '2') {
				$success = "VM start command sent.";
			} elseif ($_GET['s'] == '3') {
				$success = "VM restart command sent.";
			} elseif ($_GET['s'] == '4') {
				$success = "VM shutdown command sent.";
			} elseif ($_GET['s'] == '5') {
				$success = "VM stop command sent.";
			} elseif ($_GET['s'] == '6') {
				$success = "VNC disabled.";
			} elseif ($_GET['s'] == '7') {
				$success = "VNC enabled.";
			} elseif ($_GET['s'] == '8') {
				$success = "VM console password reset successfully.";
			} elseif ($_GET['s'] == '9') {
				$success = "ISO mounted successfully.";
			} elseif ($_GET['s'] == '10') {
				$success = "ISO unmounted successfully.";
			} elseif ($_GET['s'] == '11') {
				$success = "VM disk driver updated successfully.";
			} elseif ($_GET['s'] == '12') {
				$success = "VM network driver updated successfully.";
			} elseif ($_GET['s'] == '13') {
				$success = "VM boot order updated successfully.<br />Power cycle VM to take effect.";
			} elseif ($_GET['s'] == '14') {
				$success = "VM disk resized, please login to resize inside the OS.<br />May need to power cycle VM to take effect.";
			} elseif ($_GET['s'] == '15') {
				$success = "VM disk added successfully.";
			} elseif ($_GET['s'] == '16') {
				$success = "VM disk deleted successfully.";
			} elseif ($_GET['s'] == '17') {
				$success = "VM backup started successfully.";
			} elseif ($_GET['s'] == '18') {
				$success = "VM backup deleted successfully.";
			} elseif ($_GET['s'] == '19') {
				$success = "VM restore started successfully, this might take a while.";
			} elseif ($_GET['s'] == '20') {
				$success = "VM NIC added successfully.";
			} elseif ($_GET['s'] == '21') {
				$success = "VM NIC deleted successfully.";
			}
		}
		$vm_id = $_GET['id'];
		$vm = getVMDetails($vm_id);
		$node = getNodeDetails($vm['node_id']);
	} elseif (isset($_POST['id'])) {
		$vm_id = $_POST['id'];
		$vm = getVMDetails($vm_id);
		$node = getNodeDetails($vm['node_id']);
	} else {
		header("Location: vms.php?s=3");
	}
}
#print_r($node);

header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
$csrfToken = getCSRFToken();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
	$token = $_POST["csrf_token"];
	if (validateCSRFToken($token)) {
		if (isset($_POST['update_vm'])) {
			$encpw = encrypt($_POST["vncpw"]);
			$vm_data = [':name' => $_POST["name"],':hostname' => $_POST["hostname"],':notes' => isset($_POST["notes"])? $_POST["notes"]: ' ',':vncpw' => $encpw,':vncport' => $_POST["vncport"],':websockify' => $_POST["websockify"],':mac_address' => $_POST["mac_address"],':cluster' => $_POST["cluster"],':status' => isset($_POST["status"])? 1: 0,':protected' => isset($_POST["protected"])? 1: 0];
			$result = editVM($vm_id,$vm_data);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=1");
			} else {
				$error = "VM update failed: ".$result;
			}
		}
		if (isset($_POST['set_CPU'])) {
			$cpu_cores = $_POST["cpu_cores"];
			$result = setCPU($vm_id,$vm['name'],$cpu_cores,$node['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=1");
			} else {
				$error = "VM update failed: ".$result;
			}
		}
		if (isset($_POST['set_RAM'])) {
			$memory = $_POST["memory"];
			$result = setRAM($vm_id,$vm['name'],$memory,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=1");
			} else {
				$error = "VM update failed: ".$result;
			}
		}
		if (isset($_POST['resize_disk'])) {
			$disk_id= $_POST["disk_id"];
			$disk_name = $_POST["disk_name"];
			$disk_size = $_POST["disk_size"];
			$result = resizeDisk($vm_id,$vm['name'],$disk_id,$disk_name,$disk_size,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=14");
			} else {
				$error = "VM disk resize failed: ".$result;
			}
		}
		if (isset($_POST['add_disk'])) {
			$disk_size = $_POST["disk_size"];
			$result = addDisk($vm_id,$vm['name'],$disk_size,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=15");
			} else {
				$error = "VM disk add failed: ".$result;
			}
		}
		if (isset($_POST['delete_disk'])) {
			$disk_id= $_POST["disk_id"];
			$disk_name = $_POST["disk_name"];
			$result = deleteDisk($vm_id,$vm['name'],$disk_id,$disk_name,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=16");
			} else {
				$error = "VM disk delete failed: ".$result;
			}
		}
		if (isset($_POST['add_nic'])) {
			$network = $_POST["network"];
			$result = addNIC($vm_id,$vm['name'],$network,$vm['mac_address'],$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=20");
			} else {
				$error = "VM NIC add failed: ".$result;
			}
		}
		if (isset($_POST['delete_nic'])) {
			$nic_id= $_POST["nic_id"];
			$mac_address = $_POST["mac_address"];
			$result = deleteNIC($vm['node_id'],$vm['name'],$nic_id,$mac_address);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=21");
			} else {
				$error = "VM NIC delete failed: ".$result;
			}
		}
		if (isset($_POST['set_iow'])) {
			$speed = $_POST['iow'];
			$result = setIOW($vm_id,$vm['name'],$speed,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=1");
			} else {
				$error = "VM update failed: ".$result;
			}
		}
		if (isset($_POST['set_iow'])) {
			$speed = $_POST['iow'];
			$result = setIOW($vm_id,$vm['name'],$speed,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=1");
			} else {
				$error = "VM update failed: ".$result;
			}
		}
		if (isset($_POST['set_nic'])) {
			$speed = $_POST['nic'];
			$result = setNIC($vm_id,$vm['name'],$vm['network'],$speed,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=1");
			} else {
				$error = "VM update failed: ".$result;
			}
		}
		if (isset($_POST['startvm'])) {
			$result = startVM($vm_id,$vm['name'],$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=2");
			} else {
				$error = "VM start failed: ".$result;
			}
		}
		if (isset($_POST['restartvm'])) {
			$result = restartVM($vm_id,$vm['name'],$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=3");
			} else {
				$error = "VM restart failed: ".$result;
			}
		}
		if (isset($_POST['shutdownvm'])) {
			$result = shutdownVM($vm_id,$vm['name'],$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=4");
			} else {
				$error = "VM shutdown failed: ".$result;
			}
		}
		if (isset($_POST['stopvm'])) {
			$result = stopVM($vm_id,$vm['name'],$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=5");
			} else {
				$error = "VM stop failed: ".$result;
			}
		}
		if (isset($_POST['disableVNC'])) {
			$result = disableVNC($vm_id,$vm['name'],$vm['websockify'],$vm['vncport'],$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=6");
			} else {
				$error = "VM disable VNC failed: ".$result;
			}
		}
		if (isset($_POST['enableVNC'])) {
			$result = enableVNC($vm_id,$vm['name'],$vm['websockify'],$vm['vncport'],$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=7");
			} else {
				$error = "VM enable VNC failed: ".$result;
			}
		}
		if (isset($_POST['consolePW'])) {
			$result = consolePW($vm_id,$vm['name'],$vm['vncport'],$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=8");
			} else {
				$error = "VM console password reset failed: ".$result;
			}
		}
		if (isset($_POST['mountISO'])) {
			$ostemplate = $_POST['ostemplate'];
			$result = mountISO($vm_id,$vm['name'],$ostemplate,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=9");
			} else {
				$error = "VM ISO mount failed: ".$result;
			}
		}
		if (isset($_POST['unmountISO'])) {
			$result = unmountISO($vm_id,$vm['name'],$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=10");
			} else {
				$error = "VM ISO unmount failed: ".$result;
			}
		}
		#if (isset($_POST['diskDriver'])) {
		#	$bus = $_POST['bus'];
		#	$result = diskDriver($vm_id,$vm['name'],$bus,$vm['node_id']);
		#	if($result === true) {
		#		header("Location: vm.php?id=". (int)$vm_id. "&s=11");
		#	} else {
		#		$error = "VM update disk driver failed: ".$result;
		#	}
		#}
		#if (isset($_POST['netDriver'])) {
		#	$bus = $_POST['bus'];
		#	$result = netDriver($vm_id,$vm['name'],$bus,$vm['node_id']);
		#	if($result === true) {
		#		header("Location: vm.php?id=". (int)$vm_id. "&s=12");
		#	} else {
		#		$error = "VM update network driver failed: ".$result;
		#	}
		#}
		if (isset($_POST['bootOrder'])) {
			$boot = $_POST['boot'];
			$result = bootOrder($vm_id,$vm['name'],$boot,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=13");
			} else {
				$error = "VM update boot order failed: ".$result;
			}
		}
		if (isset($_POST['backupvm'])) {
			$result = backupVM($vm_id,$vm['name'],$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=17");
			} else {
				$error = "VM backup failed: ".$result;
			}
		}
		if (isset($_POST['deleteBackup'])) {
			$backup_id = $_POST['backup_id'];
			$backup_name = $_POST['backup_name'];
			$result = deleteBackup($vm_id,$backup_name,$backup_id,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=18");
			} else {
				$error = "VM backup delete failed: ".$result;
			}
		}
		if (isset($_POST['restoreVM'])) {
			$backup_name = $_POST['backup_name'];
			$result = restoreVM($backup_name,$vm['name'],$vm['vncport'],$vm_id,$vm['node_id']);
			if($result === true) {
				header("Location: vm.php?id=". (int)$vm_id. "&s=19");
			} else {
				$error = "VM restore failed: ".$result;
			}
		}
		if (isset($_POST['destroyVM'])) {
			if (isset($_POST['confirm'])) {
				$confirm = $_POST['confirm'];
				$result = destroyVM($vm_id,$vm['name'],$vm['websockify'],$vm['vncport'],$vm['node_id'],$confirm);
				if($result === true) {
					header("Location: vms.php?s=2");
				} else {
					$error = "VM delete failed: ".$result;
				}
			} else {
				$error = "VM delete failed: Please make sure you checked the confirmation box.";
			}
		}
	} else {
		$error = "Invalid CSRF token.";
	}
}

if ($vm) {
	$clusters = getClusters('all');
	if ($vm['status'] == "1") {
		$state = " checked";
	} else {
		$state = "";
	}
	if ($vm['protected'] == "1") {
		$protect = " checked";
	} else {
		$protect = "";
	}
	$isoList = getISOs();
	$disks = getDisks($vm_id);
	$backups = getBackups($vm_id);
	$nics = getNICs($vm_id);
	$networks = getNetworks($vm['node_id']);
?>
<!DOCTYPE html>
<html lang="en">
<?php include('header.php'); ?>
<body>
	<nav>
		<input type="checkbox" id="check">
		<label for="check" class="checkbtn">
			<i class="fas fa-bars"></i>
		</label>
		<label class="logo"><a href="index.php"><img src="assets/logo.png" alt="KontrolVM Logo"></a></label>
		<ul>
			<li><a href="index.php">Dashboard</a></li>
			<?php if (in_array($myrole, ['2', '9'])) { ?> <li><a class="active" href="clusters.php">Infrastructure</a></li> <?php } ?>
			<?php if (in_array($myrole, ['1', '9'])) { ?> <li><a href="users.php">Users</a></li> <?php } ?>
			<li><a href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<ul class="submenu">
		<li><a href="clusters.php">Clusters</a></li>
		<li><a href="nodes.php">Nodes</a></li>
		<li><a class="active" href="vms.php">VMs</a></li>
	</ul>
	<div class="container">
		<div id="server-status" style="float:right;"> 
			<img src="assets/loading.gif" alt="Loading..."> 
		</div>
		<h1>VM Details</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="actionButtons">
			<form id="startvm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
				<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
				<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
			<button type="submit" name="startvm" id="startvm" class="btnaction"><i class="fa-solid fa-play tooltip"><span class="tooltiptext">Start VM</span></i></button></form>
			<form id="restartvm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
				<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
				<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
			<button type="submit" name="restartvm" id="restartvm" class="btnaction"><i class="fa-solid fa-arrow-rotate-right tooltip"><span class="tooltiptext">Restart VM</span></i></button></form>
			<form id="shutdownvm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
				<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
				<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
			<button type="submit" name="shutdownvm" id="shutdownvm" class="btnaction"><i class="fa-solid fa-power-off tooltip"><span class="tooltiptext">Shutdown VM</span></i></button></form>
			<form id="stopvm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
				<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
				<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
			<button type="submit" name="stopvm" id="stopvm" class="btnaction"><i class="fa-solid fa-stop tooltip"><span class="tooltiptext">Stop VM</span></i></button></form>
			<form id="consolePW" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
				<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
				<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
			<button type="submit" name="consolePW" id="consolePW" class="btnaction"><i class="fa-solid fa-key tooltip"><span class="tooltiptext">Reset VNC Password</span></i></button></form>
			<?php if ($vm['vncexpire'] == '1') { ?>
				<form id="enableVNC" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
					<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
					<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
				<button type="submit" name="enableVNC" id="enableVNC" class="btnaction"><i class="fa-solid fa-terminal tooltip"><span class="tooltiptext">Enable VNC</span></i></button></form>
			<?php } else { ?>
				<form id="disableVNC" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
					<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
					<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
				<button type="submit" name="disableVNC" id="disableVNC" class="btnaction"><i class="fa-solid fa-terminal tooltip" style="text-decoration:line-through;text-decoration-color:red;text-decoration-thickness:4px;"><span class="tooltiptext">Disable VNC</span></i></button></form>
				<button type="button" class="btnaction" onclick="openPopup('https://<?php echo $node['ipaddr']; ?>:<?php echo $vm['websockify']; ?>/vnc.html?autoconnect=true&encrypt=true&password=<?php echo decrypt($vm['vncpw']); ?>', 1320, 830)"><i class="fa-solid fa-desktop tooltip"><span class="tooltiptext">HTML5 Console</span></i></button>
			<?php } ?>
			<script>
			function openPopup(url, width, height) {
				var popupWindow = window.open(url, "_blank", "width=" + width + ",height=" + height + ",scrollbars=yes");
				popupWindow.focus();
			}
			</script>
		</div>
		<div class="table-container"">
			<div class="node-details">
				<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
				<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
				<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
				<table>
					<tbody>
						<tr>
							<td style="background-color:#999;">Hostname:</td>
							<td><input type="text" id="hostname" name="hostname" value="<?php echo htmlspecialchars($vm['hostname']);?>" style="text-align:center;width:80%;"></td> 
						</tr>
						<tr>
							<td style="background-color:#999;">Node:</td>
							<td><a href='node.php?id=<?php echo htmlspecialchars($vm['node_id']); ?>'><?php echo htmlspecialchars($node['hostname']); ?></a></td>
						</tr>
						<tr>
							<td style="background-color:#999;">Active:</td>
							<td>
								<label class="checkbox-container">
									<input type="checkbox" name="status"<?php echo $state; ?>>
									<span class="checkmark"></span>
								</label>
							</td>
						</tr>
						<tr>
							<td style="background-color:#999;">Protected:</td>
							<td>
								<label class="checkbox-container">
									<input type="checkbox" name="protected"<?php echo $protect; ?>>
									<span class="checkmark"></span>
								</label>
							</td>
						</tr>
						<tr>
							<td style="background-color:#999;">Notes:</td>
							<td><input type="text" id="notes" name="notes" value="<?php echo htmlspecialchars($vm['notes']);?>" style="text-align:center;width:80%;"></td> 
						</tr>
						<tr>
							<td style="background-color:#999;">Cluster:</td>
							<td><select id="myInput9" name="cluster" style="text-align:center;width:80%;">
								<?php foreach ($clusters as $cluster):?>
									<?php if($cluster['cluster_id'] == $vm['cluster']) { ?>
										<option value="<?php echo htmlspecialchars($cluster['cluster_id']);?>" selected> 
									<?php } else { ?>
										<option value="<?php echo htmlspecialchars($cluster['cluster_id']);?>">
									<?php } ?>
								<?php echo htmlspecialchars($cluster['friendlyname']);?> 
									</option>
								<?php endforeach;?>
								</select>
							</td>
						</tr>
						<tr>
							<td style="background-color:#999;">Name:</td>
							<td><input type="text" id="myInput1" name="name" value="<?php echo htmlspecialchars($vm['name']);?>" style="text-align:center;width:60%;" readonly> <input type="checkbox" id="enablemyInput1" onchange="toggleInput('myInput1')"> Override</td> 
						</tr>
						<tr>
							<td style="background-color:#999;">MAC Address:</td>
							<td><input type="text" id="myInput3" name="mac_address" value="<?php echo htmlspecialchars($vm['mac_address']);?>" style="text-align:center;width:60%;" readonly> <input type="checkbox" id="enablemyInput3" onchange="toggleInput('myInput3')"> Override</td>
						</tr>
						<tr>
							<td style="background-color:#999;">VNC Password:</td>
							<td><input type="text" id="myInput5" name="vncpw" value="<?php echo htmlspecialchars(decrypt($vm['vncpw']));?>" style="text-align:center;width:60%;" readonly> <input type="checkbox" id="enablemyInput5" onchange="toggleInput('myInput5')"> Override</td>
						</tr>
						<tr>
							<td style="background-color:#999;">VNC Port:</td>
							<td><input type="text" id="myInput6" name="vncport" value="<?php echo htmlspecialchars($vm['vncport']);?>" style="text-align:center;width:60%;" readonly> <input type="checkbox" id="enablemyInput6" onchange="toggleInput('myInput6')"> Override</td>
						</tr>
						<tr>
							<td style="background-color:#999;">Websockify:</td>
							<td><input type="text" id="myInput7" name="websockify" value="<?php echo htmlspecialchars($vm['websockify']);?>" style="text-align:center;width:60%;" readonly> <input type="checkbox" id="enablemyInput7" onchange="toggleInput('myInput7')"> Override</td>
						</tr>
						<tr>
							<td style="background-color:#999;">Created At:</td>
							<td><?php echo date('m/j/Y @ g:i:s A', $vm['created_at']); ?></td>
						</tr>
						<tr>
							<td style="background-color:#999;">Last Updated:</td>
							<td><?php echo date('m/j/Y @ g:i:s A', $vm['last_updated']); ?></td>
						</tr>
					</tbody>
				</table>
				<br />
				<br />
				<center><button type="submit" class="stylish-button" name="update_vm" id="update_vm">SAVE VM</button><br /></center>
				</form>
				<br />
				<hr />
				<br />
				<h2>Disk Management</h2>
				<div class="disk-list">
						<form id="add_disk" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<h3>Add New Disk</h3>
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<input type="number" id="disk_size" name="disk_size" placeholder="10" style="text-align:center;width:80px;"> GB <button class="stylish-button" id="add_disk" name="add_disk">Add Disk</button>
						</form>
					<br />
					<hr />
					<br />
					<h3>Attached Disks</h3>
					<?php foreach ($disks as $disk):
						$name = $disk['disk_name'];
						$size = $disk['disk_size'];
						$disk_id = $disk['disk_id'];
						$csrf = '<input type="hidden" name="csrf_token" value="'.$csrfToken.'">';
						$diskname = '<input type="hidden" name="disk_name" value="'.$name.'">';
						$diskid = '<input type="hidden" name="disk_id" value="'.$disk_id.'">';
						echo "<form id='resize_disk' action='vm.php?id=$vm_id' method='post'>$csrf $diskname $diskid $name : <input type='text' id='disk_size' name='disk_size' value='$size' style='text-align:center;width:80px;'> GB <button class='stylish-button' id='resize_disk' name='resize_disk'>Resize</button> <button class='stylish-button' id='delete_disk' name='delete_disk'>Delete</button></form>";
					endforeach;?>
				</div>
				<br />
				<hr />
				<br />
				<h2>Network Management</h2>
				<div class="disk-list">
						<form id="add_nic" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<h3>Add New NIC</h3>
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<select id="network" name="network" style="text-align:center;width:150px;">
						<?php foreach ($networks as $network):?>
							<option value="<?php echo htmlspecialchars($network['net_name']);?>">
							<?php echo htmlspecialchars($network['net_name']);?> 
							</option>
						<?php endforeach;?>
						</select>
						<button class="stylish-button" id="add_nic" name="add_nic">Add NIC</button>
						</form>
					<br />
					<hr />
					<br />
					<h3>Attached NICs</h3>
					<?php foreach ($nics as $nic):
						$nic_name = $nic['nic_name'];
						$nic_id = $nic['nic_id'];
						$mac = $nic['mac_address'];
						$csrf = '<input type="hidden" name="csrf_token" value="'.$csrfToken.'">';
						$macaddr = '<input type="hidden" name="mac_address" value="'.$mac.'">';
						$nic_id = '<input type="hidden" name="nic_id" value="'.$nic_id.'">';
						echo "<form id='delete_nic' action='vm.php?id=$vm_id' method='post'>$csrf $macaddr $nic_id $nic_name <button class='stylish-button' id='delete_nic' name='delete_nic'>Delete</button></form>";
					endforeach;?>
				</div>
				<br />
				<hr />
				<br />
				<h2>Backup/Restore</h2>
				<div class="disk-list">
						<form id="backupvm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<button class="stylish-button" id="backupvm" name="backupvm">Backup</button>
						</form>
					<br />
					<hr />
					<br />
					<h3>Backups</h3>
					<?php foreach ($backups as $backup):
						$backup_name = $backup['backup_name'];
						$size = $backup['backup_size'];
						getBackupInfo($backup_name,$vm['node_id']);
						if($size > 0) {
							$size = $size."MB";
						} else {
							$size = "<b>IN PROGRESS</b>";
						}
						$backup_id = $backup['backup_id'];
						$created_at = $backup['created_at'];
						$csrf = '<input type="hidden" name="csrf_token" value="'.$csrfToken.'">';
						$backupname = '<input type="hidden" name="backup_name" value="'.$backup_name.'">';
						$backup_id = '<input type="hidden" name="backup_id" value="'.$backup_id.'">';
						echo "<form id='deleteBackup' action='vm.php?id=$vm_id' method='post'>$csrf $backupname $backup_id $backup_name | $size | ".date('m/j/Y @ g:i:s A', $created_at)." <button class='stylish-button' id='restoreVM' name='restoreVM'>Restore</button> <button class='stylish-button' id='deleteBackup' name='deleteBackup'>Delete</button></form><br />";
					endforeach;?>
				</div>
				<br />
				<hr />
				<br />
				<table>
					<tr>
						<td style="background-color:#999;">CPU Cores:</td>
						<td>
						<form id="set_CPU" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<input type="text" id="cpu_cores" name="cpu_cores" value="<?php echo htmlspecialchars($vm['cpu_cores']);?>" style="text-align:center;width:60%;">
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<button type="submit" name="set_CPU" id="set_CPU" class="stylish-button">SET</button></form>
						</td>
					</tr>
					<tr>
						<td style="background-color:#999;">Memory(GB):</td>
						<td>
						<form id="set_RAM" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<input type="text" id="memory" name="memory" value="<?php echo htmlspecialchars($vm['memory']);?>" style="text-align:center;width:60%;">
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<button type="submit" name="set_RAM" id="set_RAM" class="stylish-button">SET</button></form>
						</td>
					</tr>
					<tr>
						<td style="background-color:#999;">IO Write Limit:</td>
						<td>
						<form id="iow" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<select name="iow" style="text-align:center;width:60%;">
							<option value="<?php echo $vm['iow']; ?>" selected><?php echo $vm['iow']; ?>MB/s</option>
							<option value="1">1MB/s</option>
							<option value="5">5MB/s</option>
							<option value="10">10MB/s</option>
							<option value="50">50MB/s</option>
							<option value="100">100MB/s</option>
							<option value="200">200MB/s</option>
							<option value="300">300MB/s</option>
							<option value="400">400MB/s</option>
							<option value="500">500MB/s</option>
							<option value="1000">1000MB/s</option>
						</select>
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<button type="submit" name="set_iow" id="set_iow" class="stylish-button">SET</button></form>
						</td>
					</tr>
					<tr>
						<td style="background-color:#999;">NIC Speed:</td>
						<td>
						<form id="nic" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<select name="nic" style="text-align:center;width:60%;">
							<option value="<?php echo $vm['nic']; ?>" selected><?php echo $vm['nic']; ?>MB/s</option>
							<option value="1">1Mbps</option>
							<option value="5">5Mbps</option>
							<option value="10">10Mbps</option>
							<option value="50">50Mbps</option>
							<option value="100">100Mbps</option>
							<option value="500">500Mbps</option>
							<option value="1000">1000Mbps</option>
						</select>
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<button type="submit" name="set_nic" id="set_nic" class="stylish-button">SET</button></form>
						</td>
					</tr>
				</table>
				<br />
				<hr />
				<br />
				<table>
					<!--<tr>
						<td style="background-color:#999;">Net Driver:</td>
						<td>
						<form id="netdriver" action="<?php #echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<select name="bus" style="text-align:center;width:60%;">
							<option value="<?php #echo $vm['netdriver']; ?>" selected><?php #echo $vm['netdriver']; ?></option>
							<option value="e1000">e1000 (Compatibility)</option>
							<option value="virtio">virtio (Performance)</option>
						</select>
						<input type="hidden" name="csrf_token" value="<?php #echo #$csrfToken; ?>">
						<input type="hidden" name="id" value="<?php #echo $vm_id; ?>">
						<button type="submit" name="netDriver" id="netDriver" class="stylish-button">SET</button></form>
						</td>
					</tr>
					<tr>
						<td style="background-color:#999;">Disk Driver:</td>
						<td>
						<form id="diskdriver" action="<?php #echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<select name="bus" style="text-align:center;width:60%;">
							<option value="<?php #echo $vm['diskdriver']; ?>" selected><?php #echo $vm['diskdriver']; ?></option>
							<option value="ide">ide (Compatibility)</option>
							<option value="virtio">virtio (Performance)</option>
						</select>
						<input type="hidden" name="csrf_token" value="<?php #echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php #echo $vm_id; ?>">
						<button type="submit" name="diskDriver" id="diskDriver" class="stylish-button">SET</button></form>
						</td>
					</tr>-->
					<?php if ($vm['os_template'] == "kvm") { ?>
					<tr>
						<td style="background-color:#999;">Mount ISO:</td>
						<td>
						<form id="mountISO" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<select name="ostemplate" style="text-align:center;width:60%;">
							<?php foreach ($isoList as $iso):?>
								<option value="<?php echo htmlspecialchars($iso['filename']);?>"> 
							<?php echo htmlspecialchars($iso['friendlyname']);?> 
								</option>
							<?php endforeach;?>
						</select>
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<button type="submit" name="mountISO" id="mountISO" class="stylish-button">MOUNT</button></form>
						</td>
					</tr>
					<?php } else { ?>
					<tr>
						<td style="background-color:#999;">Unmount ISO:</td>
						<td>
						<form id="unmountISO" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<button type="submit" name="unmountISO" id="unmountISO" class="stylish-button">UNMOUNT</button></form>
						</td>
					</tr>
					<?php }?>
					<tr>
						<td style="background-color:#999;">Boot Order:</td>
						<td>
						<form id="bootorder" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<select name="boot" style="text-align:center;width:60%;">
						<?php if ($vm['bootorder'] == "cdrom") { ?>
							<option value="cdrom" selected>CDROM</option>
							<option value="hd">Disk</option>
						<?php } else { ?>
							<option value="cdrom">CDROM</option>
							<option value="hd" selected>Disk</option>
						<?php }?>
						</select>
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<button type="submit" name="bootOrder" id="bootOrder" class="stylish-button">SET</button></form>
						</td>
					</tr>
				</table>
				<?php if ($vm['protected'] == "0" AND $vm['status'] == "0") { ?>
				<br />
				<hr />
				<br />
				<table>
					<tr>
						<td style="background-color:#999;">DELETE VM:</td>
						<td style="padding:10px;">
						<form id="destroyVM" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<label class="checkbox-container" style="padding:5px;">
							<input type="checkbox" name="confirm" style="padding:5px;">
							<span class="checkmark"></span>
						</label>
						Confirm
						</td>
						<td>
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $vm_id; ?>">
						<button type="submit" name="destroyVM" id="destroyVM" class="stylish-button" style="background-color:red;">DELETE</button>
						</form>
						</td>
					</tr>					
				</table>
				<?php } ?>
			</div>
<?php
} else {
	logError("Error finding VM.");
	header("Location: vms.php?s=3");
}
?>
		</div>
	</div>
	<?php include('footer.php'); ?>
	<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
	<script src="assets/filtertable.js"></script>
	<script>
		// Unlock field is override is checked.
		function toggleInput(inputId) {
			const checkboxId = 'enable' + inputId;
			const checkbox = document.getElementById(checkboxId);
			const inputField = document.getElementById(inputId);
			if (checkbox) { // Check if checkbox exists
				inputField.readOnly =!checkbox.checked;
			} else {
				console.error("Checkbox not found:", checkboxId);
			}
		}
		
		// JavaScript code to handle theme switching (from previous responses)
		const themeToggle = document.getElementById('theme-toggle');
		const body = document.body;

		// Load the user's preferred theme from localStorage
		const savedTheme = localStorage.getItem('theme');
		if (savedTheme === 'dark') {
			body.classList.add('dark-mode');
			themeToggle.checked = true; 
		}

		themeToggle.addEventListener('change', () => {
			if (themeToggle.checked) {
				body.classList.add('dark-mode');
				localStorage.setItem('theme', 'dark');
			} else {
				body.classList.remove('dark-mode');
				localStorage.setItem('theme', 'light');
			}
		});
		function updateVmStatus(vmname,node_id) {
			const statusDiv = document.getElementById('server-status');
			$.post("./get_vm_status.php", { 
				vmname: vmname, 
				node_id: node_id
			}, function(data) {
				if (data == "running") {
					statusDiv.innerHTML = "<img src='assets/online.png' height='24' width='24' alt='Running'>";
				} else {
					statusDiv.innerHTML = "<img src='assets/offline.png' height='24' width='24' alt='Stopped'>";
				}
			});
		}
		updateVmStatus('<?php echo $vm['name'];?>','<?php echo $vm['node_id'];?>');
		setInterval(function() {
			updateVmStatus('<?php echo $vm['name'];?>','<?php echo $vm['node_id'];?>');
		}, 15000);
	</script>
</body>
</html>