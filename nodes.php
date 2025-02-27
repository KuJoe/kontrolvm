<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php"); 
	exit; 
} else {
	if(isset($_GET['s']) ) {
		if($_GET['s'] == '1') {
			$success = "Node added successfully.";
		} elseif ($_GET['s'] == '2') {
			$success = "Nodes updated.";
		} elseif ($_GET['s'] == '3') {
			$error = "Node ID missing.";
		}
	}
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
	$allowedRoles = ['2', '9'];
	if (!in_array($chkRole, $allowedRoles)) {
		header("Location: home.php?s=99");
		exit;
	}
	if (isset($_GET['update']) AND $_GET['update'] == '1') {
		include('updateNodes.php');
		header("Location: nodes.php?state=all&s=2");
	}
}
if ($_SERVER["REQUEST_METHOD"] == "POST") {
	$token = $_POST["csrf_token"];
	if (validateCSRFToken($token)) {
		$hostname = $_POST["hostname"];
		$ipaddr = $_POST["ipaddr"];
		$sshport = $_POST["sshport"];
		$cluster = $_POST["cluster"];
		$rootpw = $_POST["rootpw"];
		$result = addNode($hostname, $ipaddr, $sshport, $rootpw, $cluster);
		if($result === true) {
			include('updateNodes.php');
			header("Location: nodes.php?state=all&s=1");
		} else {
			$error = "Node add failed: ".$result;
		}
	} else {
		$error = "Invalid CSRF token.";
	}
}
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
$csrfToken = getCSRFToken();
if(isset($_GET['state']) AND $_GET['state'] == "all") {
	$servers = getServerList('all');
} else {
	$servers = getServerList('1');
}
$clusters = getClusters('1');
$script_name = 'updateNodes.php';
$last_run_time = getLastRunTime($script_name); 
if ((!$last_run_time || time() - $last_run_time >= 3600) AND isset($bgupdate)) {
	include($script_name);
	$last_run_time = time();
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
			<?php if (in_array($myrole, ['2', '9'])) { ?> <li><a class="active" href="clusters.php">Infrastructure</a></li> <?php } ?>
			<?php if (in_array($myrole, ['1', '9'])) { ?> <li><a href="users.php">Users</a></li> <?php } ?>
			<li><a href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<ul class="submenu">
		<li><a href="clusters.php">Clusters</a></li>
		<li><a class="active" href="nodes.php">Nodes</a></li>
		<li><a href="vms.php">VMs</a></li>
	</ul>
	<div class="container">
		<p style="float:right;"><button id="addBtn" class="stylish-button"><i class="fa-solid fa-square-plus"></i> ADD NODE</button></p>
		<div id="addModal" class="modal">
			<div class="modal-content">
				<span class="close">&times;</span>
				<h2>Add New Node</h2>
				<br />
				<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post"> 
					<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
					<label for="hostname">Hostname:</label>
					<input type="text" id="hostname" name="hostname" required><br><br>
					<label for="ipaddr">IP Address:</label>
					<input type="text" id="ipaddr" name="ipaddr" required><br><br>
					<label for="sshport">SSH Port:</label>
					<input type="text" id="sshport" name="sshport" required><br><br>
					<label for="rootpw">Root Password:</label>
					<input type="password" id="rootpw" name="rootpw" required><br><br>
					<label for="cluster">Cluster:</label>
					<select name="cluster">
					<?php foreach ($clusters as $cluster):?>
							<option value="<?php echo htmlspecialchars($cluster['cluster_id']);?>">
					<?php echo htmlspecialchars($cluster['friendlyname']);?> 
						</option>
					<?php endforeach;?>
					</select><br /><br />
					<center><button type="submit" class="stylish-button"><i class="fa-solid fa-square-plus"></i> ADD NODE</button></center>
				</form>
			</div>
		</div>
		<h1>Nodes</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="table-container" style="max-width:1500px;">
		<input type="text" id="serverInput" oninput="filterServerTable()" placeholder="Search servers">
		<table id="server_table">
			<thead>
				<tr>
					<th>Server</th>
					<th>Online</th>
					<th><i class="fa-solid fa-microchip"></i></th>
					<th><i class="fa-solid fa-memory"></i></th>
					<th><i class="fa-solid fa-hard-drive"></i></th>
				</tr>
			</thead>
			<tbody>
			<?php
				foreach ($servers as $server) {
					$node_id = $server['node_id'];
					$connection = @fsockopen($server['ipaddr'], $server['sshport'], $errno, $errstr, 2);
					if (is_resource($connection)) {
						$online = "<img src='assets/1.png' alt='Online' />";
						fclose($connection);
					} else {
						$online = "<img src='assets/0.png' alt='Offline' />";
					}
					echo "<tr><td class='tname'><a href='node.php?id=$node_id'>" . $server['hostname'] . "</a></td>";
					echo "<td>$online</td>";
					echo "<td><span class='ticon'><i class='fa-solid fa-microchip'></i></span> " . $server['load'] . "</td>";
					echo "<td><span class='ticon'><i class='fa-solid fa-memory'></i></span> " . $server['memused'] . "</td>";
					echo "<td><span class='ticon'><i class='fa-solid fa-hard-drive'></i></span> " . $server['diskclnt'] . "</td></tr>";
				}
			?>
			</tbody>
		</table>
		</div>
		<p style="text-align:center;padding:10px;font-weight:bold;"><a href="nodes.php?state=all">View All</a></p>
		<p style="text-align:center;padding:10px;font-weight:bold;"><a href="nodes.php?update=1">Refresh Nodes</a></p>
		<p style="text-align:center;font-size:12px;">Last refresh:<br /><?php echo date('m/j/Y @ g:i:s A',$last_run_time); ?></p>
	</div>
	<?php include('footer.php'); ?>
	<script>
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
		var modal = document.getElementById("addModal");

		// Get the button that opens the modal
		var btn = document.getElementById("addBtn");

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