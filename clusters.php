<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php"); 
	exit; 
} else {
	if (isset($_GET['s']) AND $_GET['s'] == '1') {
		$success = "Cluster added successfully.";
	}
	if (isset($_GET['s']) AND $_GET['s'] == '2') {
		$success = "Cluster deleted successfully.";
	}
	if (isset($_GET['s']) AND $_GET['s'] == '3') {
		$success = "Cluster enabled successfully.";
	}
	if (isset($_GET['s']) AND $_GET['s'] == '4') {
		$success = "Cluster disabled successfully.";
	}
	define('AmAllowed', TRUE);
	require_once('config.php');
	require_once('functions.php');
	$loggedin_id = $_SESSION['staff_id'];
	$chkActive = checkActive($loggedin_id);
	$chkLocked = checkLockedOut($loggedin_id);
	if($chkLocked == true OR $chkActive == false) {
		header("Location: logout.php");
		exit;
	}
}
if ($_SERVER["REQUEST_METHOD"] == "POST") {
	$token = $_POST["csrf_token"];
	if (validateCSRFToken($token)) {
		if (isset($_POST['add_cluster'])) {
			$loc = $_POST["loc"];
			$friendlyname = $_POST["friendlyname"];
			$result = addCluster($loc, $friendlyname);
			if($result === true) {
				header("Location: clusters.php?s=1");
			} else {
				$error = "Cluster add failed: ".$result;
			}
		}
		if (isset($_POST['delete_cluster'])) {
			$clusterid = $_POST['clusterid'];
			$result = deleteCluster($clusterid);
			if($result === true) {
				header("Location: clusters.php?s=2");
			} else {
				$error = "Cluster deletion failed: ".$result;
			}
		}
		if (isset($_POST['enable_cluster'])) {
			$clusterid = $_POST['clusterid'];
			$result = enableCluster($clusterid);
			if($result === true) {
				header("Location: clusters.php?s=3");
			} else {
				$error = "Enabling cluster failed: ".$result;
			}
		}
		if (isset($_POST['disable_cluster'])) {
			$clusterid = $_POST['clusterid'];
			$result = disableCluster($clusterid);
			if($result === true) {
				header("Location: clusters.php?s=4");
			} else {
				$error = "Disabling cluster failed: ".$result;
			}
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
$clusters = getClusters('all');
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
			<li><a href="nodes.php">Nodes</a></li>
			<li><a href="vms.php">VMs</a></li>
			<li><a href="users.php">Users</a></li>
			<li><a class="active" href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<ul class="submenu">
		<li><a href="settings.php">General</a></li>
		<li><a class="active" href="clusters.php">Clusters</a></li>
		<li><a href="isos.php">ISOs</a></li>
		<li><a href="ipv4.php">IPv4 Addresses</a></li>
		<li><a href="ipv6.php">IPv6 Addresses</a></li>
	</ul>
	<div class="container">
		<p style="float:right;"><button id="addBtn" class="stylish-button"><i class="fa-solid fa-square-plus"></i> ADD CLUSTER</button></p>
		<div id="addModal" class="modal">
			<div class="modal-content">
				<span class="close">&times;</span>
				<h2>Add New Cluster</h2>
				<br />
				<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post"> 
					<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
					<label for="loc">Cluster Identifier:</label>
					<input type="text" id="loc" name="loc" placeholder="ie: us1, cluster01, homelab" maxlength="20" required><br><br>
					<label for="friendlyname">Friendly Name:</label>
					<input type="text" id="friendlyname" name="friendlyname" maxlength="20" required><br><br>
					<center><button type="submit" class="stylish-button" name="add_cluster"><i class="fa-solid fa-square-plus"></i> ADD IP</button></center>
				</form>
			</div>
		</div>
		<h1>Clusters</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="table-container" style="max-width:1500px;">
		<input type="text" id="serverInput" oninput="filterServerTable()" placeholder="Search Clusters">
		<table id="server_table">
			<thead>
				<tr>
					<th>Cluster Name</th>
					<th>Status</th>
					<th>Notes</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody>
			<?php
				foreach ($clusters as $cluster) {
					$clusterid = $cluster['clusterid'];
					echo '<tr>';
					echo "<td class='tname'>" . $cluster['friendlyname'] . "</td>";
					echo "<td><span class='ticon' style='padding-right:4px;'>Status: </span>";
					if ($cluster['status'] == "1") {
						echo "<img src='assets/1.png' alt='Enabled'>";
					} else {
						echo "<img src='assets/0.png' alt='Disabled'>";
					}
					echo "</td>";
					echo "<td style='font-size:small;'>" . $cluster['notes'] . "</td><td>";
					echo '<form style="padding:10px;" action="'.htmlspecialchars($_SERVER["PHP_SELF"]).'" method="post"> 
							<input type="hidden" name="csrf_token" value="'.$csrfToken.'">
							<input type="hidden" name="clusterid" value="'.$clusterid.'">
							<button type="submit" class="stylish-button" name="delete_cluster">Delete</button>
						  </form>';
					echo '<form style="padding:10px;" action="'.htmlspecialchars($_SERVER["PHP_SELF"]).'" method="post">  
							<input type="hidden" name="csrf_token" value="'.$csrfToken.'">
							<input type="hidden" name="clusterid" value="'.$clusterid.'">';
					if ($cluster['status'] == "1") {
						echo '<button type="submit" class="stylish-button" name="disable_cluster">Disable</button>';
					} else {
						echo '<button type="submit" class="stylish-button" name="enable_cluster">Enable</button>';
					}
					echo '</form>';
					echo '</td></tr>';
				}
			?>
			</tbody>
		</table>
		</div>
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