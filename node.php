<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
define('AmAllowed', TRUE);
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php");
	exit; 
} else {
	if (isset($_GET['id'])) {
		if (isset($_GET['s']) AND $_GET['s'] == '1') {
			$success = "Node updated successfully.";
		}
		$node_id = $_GET['id'];
		require_once('functions.php');
		$node = getNodeDetails($node_id);
	} elseif (isset($_POST['id'])) {
		$node_id = $_POST['id'];
		require_once('functions.php');
		$node = getNodeDetails($node_id);
	} else {
		error_log("Error node ID missing.");
		exit;
	}
}
$loggedin_id = $_SESSION['staff_id'];
$chkActive = checkActive($loggedin_id);
$chkLocked = checkLockedOut($loggedin_id);
if($chkLocked == true OR $chkActive == false) {
	header("Location: logout.php");
	exit;
}

header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
$csrfToken = getCSRFToken();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
	$token = $_POST["csrf_token"];
	if (validateCSRFToken($token)) {
		if (isset($_POST['editNode'])) {
			$hostname = $_POST["hostname"];
			$ipaddr = $_POST["ipaddr"];
			$sshport = $_POST["sshport"];
			$lastvm = $_POST["lastvm"];
			$lastvnc = $_POST["lastvnc"];
			$lastws = $_POST["lastws"];
			$loc = $_POST["loc"];
			if($_POST["status"]) {
				$status = '1';
			} else {
				$status = '0';
			}
			$result = editNode($node_id, $hostname, $ipaddr, $sshport, $status, $lastvm, $lastvnc, $lastws, $loc);
			if($result === true) {
				header("Location: node.php?id=$node_id&s=1");
			} else {
				$error = "Node update failed: ".$result;
			}
		}
		if (isset($_POST['deleteNode'])) {
			if (isset($_POST['confirm'])) {
				$confirm = $_POST['confirm'];
				$result = deleteNode($node_id, $node['hostname'], $confirm);
				if($result === true) {
					header("Location: nodes.php?s=2");
				} else {
					$error = "Node delete failed: ".$result;
				}
			} else {
				$error = "Node delete failed: Please make sure you checked the confirmation box.";
			}
		}
	} else {
		$error = "Invalid CSRF token.";
	}
}

if ($node) {
	$clusters = getClusters('all');
	$script_name = 'updateNodes.php';
	$last_run_time = getLastRunTime($script_name); 
	if (!$last_run_time || time() - $last_run_time >= 3600) {
		include($script_name);
		updateLastRunTime($script_name); 
	}
	if ($node['status'] == "1") {
		$state = " checked";
	} else {
		$state = "";
	}
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
			<li><a class="active" href="nodes.php">Nodes</a></li>
			<li><a href="vms.php">VMs</a></li>
			<li><a href="users.php">Users</a></li>
			<li><a href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo $_SESSION["username"]; ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<div class="container">
		<h1>Node Details</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="table-container" style="max-width:1500px;">
			<div class="node-details">
				<form id="editNode" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
				<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
				<input type="hidden" name="id" value="<?php echo $node_id; ?>">
				<table>
					<tr>
						<td style="background-color:#999;">Hostname:</td>
						<td><input type="text" id="hostname" name="hostname" value="<?php echo htmlspecialchars($node['hostname']); ?>" style="text-align:center;width:80%;"></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Status:</td>
						<td>
							<label class="checkbox-container">
								<input type="checkbox" name="status"<?php echo $state; ?>>
								<span class="checkmark"></span>
							</label>
						</td>
					</tr>
					<tr>
						<td style="background-color:#999;">IP Address:</td>
						<td><input type="text" id="ipaddr" name="ipaddr" value="<?php echo htmlspecialchars($node['ipaddr']); ?>" style="text-align:center;width:80%;"></td>
					</tr>
					<tr>
						<td style="background-color:#999;">SSH Port:</td>
						<td><input type="text" id="sshport" name="sshport" value="<?php echo htmlspecialchars($node['sshport']); ?>" style="text-align:center;width:80%;"></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Cluster:</td>
						<td><select id="loc" name="loc" style="text-align:center;width:80%;">
							<?php foreach ($clusters as $cluster):?>
								<?php if($cluster['loc'] == $node['loc']) { ?>
									<option value="<?php echo htmlspecialchars($cluster['loc']);?>" selected> 
								<?php } else { ?>
									<option value="<?php echo htmlspecialchars($cluster['loc']);?>">
								<?php } ?>
							<?php echo htmlspecialchars($cluster['friendlyname']);?> 
								</option>
							<?php endforeach;?>
							</select>
					</tr>
					<tr>
						<td style="background-color:#999;">Last VM ID:</td>
						<td><input type="text" id="myInput1" name="lastvm" value="<?php echo htmlspecialchars($node['lastvm']); ?>" style="text-align:center;width:60%;" readonly> <input type="checkbox" id="enablemyInput1" onchange="toggleInput('myInput1')"> Override</td> 
					</tr>
					<tr>
						<td style="background-color:#999;">Last VNC Port:</td>
						<td><input type="text" id="myInput2" name="lastvnc" value="<?php echo htmlspecialchars($node['lastvnc']); ?>" style="text-align:center;width:60%;" readonly> <input type="checkbox" id="enablemyInput2" onchange="toggleInput('myInput2')"> Override</td> 
					</tr>
					<tr>
						<td style="background-color:#999;">Last Websockify Port:</td>
						<td><input type="text" id="myInput3" name="lastws" value="<?php echo htmlspecialchars($node['lastws']); ?>" style="text-align:center;width:60%;" readonly> <input type="checkbox" id="enablemyInput3" onchange="toggleInput('myInput3')"> Override</td> 
					</tr>
					<tr>
						<td style="background-color:#999;">CPU Cores:</td>
						<td><?php echo htmlspecialchars($node['cpu_cores']); ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Total Memory:</td>
						<td><?php echo htmlspecialchars($node['total_memory']); ?>GB</td>
					</tr>
					<tr>
						<td style="background-color:#999;">Disk Space:</td>
						<td><?php echo htmlspecialchars($node['disk_space']); ?>GB</td>
					</tr>
					<tr>
						<td style="background-color:#999;">Uptime:</td>
						<td><?php echo $node['uptime']; ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Memory Used:</td>
						<td><?php echo $node['memused']; ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Disk Usage:</td>
						<td><?php echo $node['diskclnt']; ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Load Average:</td>
						<td><?php echo $node['load']; ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Make:</td>
						<td><?php echo htmlspecialchars($node['make']); ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Model:</td>
						<td><?php echo htmlspecialchars($node['model']); ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">CPU:</td>
						<td><?php echo htmlspecialchars($node['cpu']); ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">VMs:</td>
						<td><?php echo htmlspecialchars($node['vms']); ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">OS Version:</td>
						<td><?php echo htmlspecialchars($node['os_version']); ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Kernel Version:</td>
						<td><?php echo htmlspecialchars($node['kernel_version']); ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Libvirt Version:</td>
						<td><?php echo htmlspecialchars($node['libvirt_version']); ?></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Last Updated:</td>
						<td><?php echo date('m/j/Y @ g:i:s A', $node['last_updated']); ?></td>
					</tr>
				</table>
				<br />
				<br />
				<center><button type="submit" name="editNode" id="editNode" class="stylish-button">SAVE NODE</button><br /></center>
				</form>
				<?php if ($node['status'] == "0") { ?>
				<br />
				<hr />
				<br />
				<table>
					<tr>
						<td style="background-color:#999;">DELETE NODE:</td>
						<td style="padding:10px;">
						<form id="deleteNode" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<label class="checkbox-container" style="padding:5px;">
							<input type="checkbox" name="confirm" style="padding:5px;">
							<span class="checkmark"></span>
						</label>
						Confirm
						</td>
						<td>
						<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
						<input type="hidden" name="id" value="<?php echo $node_id; ?>">
						<button type="submit" name="deleteNode" id="deleteNode" class="stylish-button" style="background-color:red;">DELETE</button>
						</form>
						</td>
					</tr>					
				</table>
				<?php } ?>
			</div>
<?php
} else {
	error_log("Error finding node.");
	exit;
}
?>
		</div>
	</div>
	<?php include('footer.php'); ?>
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
		// Get the modal
		var modal = document.getElementById("addServerModal");

		// Get the button that opens the modal
		var btn = document.getElementById("addServerBtn");

		// Get the <span> element that closes the modal
		var span = document.getElementsByClassName("close")[0];

		// When the user clicks the button, open the modal 
		btn.onclick = function() {
			modal.style.display = "block";
		}

		// When the user clicks on <span> (x), close the modal
		span.onclick = function() {
			modal.style.display = "none";
		}

		// When the user clicks anywhere outside of the modal, close it
		window.onclick = function(event) {
			if (event.target == modal) {
				modal.style.display = "none";
			}
		}
	</script>
	<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
	<script src="assets/filtertable.js"></script>
</body>
</html>