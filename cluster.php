<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
define('AmAllowed', TRUE);
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php");
	exit; 
} else {
	if(isset($_GET['id'])) {
		if(isset($_GET['s']) AND $_GET['s'] == '1') {
			$success = "Cluster updated successfully.";
		}
		if(isset($_GET['s']) AND $_GET['s'] == '2') {
			$success = "Cluster enabled successfully.";
		}
		if(isset($_GET['s']) AND $_GET['s'] == '3') {
			$success = "Cluster disabled successfully.";
		}
		$cluster_id = $_GET['id'];
		require_once('functions.php');
		$cluster = getClusterDetails($cluster_id);
	} elseif(isset($_POST['id'])) {
		$cluster_id = $_POST['id'];
		require_once('functions.php');
		$cluster = getClusterDetails($cluster_id);
	} else {
		header("Location: clusters.php?s=3");
		exit;
	}
}
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
if(!in_array($chkRole, $allowedRoles)) {
	header("Location: home.php?s=99");
	exit;
}

header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
$csrfToken = getCSRFToken();

if($_SERVER["REQUEST_METHOD"] == "POST") {
	$token = $_POST["csrf_token"];
	if(validateCSRFToken($token)) {
		if(isset($_POST['editcluster'])) {
			$cluster_data = [':friendlyname' => $_POST["friendlyname"],':deployment' => $_POST["deployment"]];
			$result = editcluster($loggedin_id,$cluster_id, $cluster_data);
			if($result === true) {
				header("Location: cluster.php?id=". (int)$cluster_id. "&s=1");
			} else {
				$error = "Cluster update failed.";
			}
		}
		if(isset($_POST['delete_cluster'])) {
			$confirm = $_POST['confirm'];
			$result = deleteCluster($loggedin_id,$cluster_id,$confirm);
			if($result === true) {
				header("Location: clusters.php?s=2");
			} else {
				$error = "Cluster deletion failed.";
			}
		}
		if(isset($_POST['enable_cluster'])) {
			$result = enableCluster($loggedin_id,$cluster_id);
			if($result === true) {
				header("Location: cluster.php?id=". (int)$cluster_id. "&s=2");
			} else {
				$error = "Enabling cluster failed.";
			}
		}
		if(isset($_POST['disable_cluster'])) {
			$result = disableCluster($loggedin_id,$cluster_id);
			if($result === true) {
				header("Location: cluster.php?id=". (int)$cluster_id. "&s=3");
			} else {
				$error = "Disabling cluster failed.";
			}
		}
	} else {
		$error = "Invalid CSRF token.";
	}
}

if($cluster) {
	if($cluster['status'] == "1") {
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
			<?php if(in_array($myrole, ['2', '9'])) { ?> <li><a class="active" href="clusters.php">Infrastructure</a></li> <?php } ?>
			<?php if(in_array($myrole, ['1', '9'])) { ?> <li><a href="users.php">Users</a></li> <?php } ?>
			<li><a href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<ul class="submenu">
		<li><a class="active" href="clusters.php">Clusters</a></li>
		<li><a href="nodes.php">Nodes</a></li>
		<li><a href="vms.php">VMs</a></li>
	</ul>
	<div class="container">
		<h1>Cluster Details</h1>
		<?php if(isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if(isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="table-container" style="max-width:1500px;">
			<div class="cluster-details">
				<form id="editcluster" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
				<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
				<input type="hidden" name="id" value="<?php echo htmlspecialchars($cluster_id); ?>">
				<table>
					<tr>
						<td style="background-color:#999;">Cluster Name:</td>
						<td><input type="text" id="friendlyname" name="friendlyname" value="<?php echo htmlspecialchars($cluster['friendlyname']); ?>" style="text-align:center;width:80%;"></td>
					</tr>
					<tr>
						<td style="background-color:#999;">Status:</td>
						<td>
							<label class="checkbox-container">
								<input type="checkbox" name="status"<?php echo $state; ?> disabled>
								<span class="checkmark"></span>
							</label>
						</td>
					</tr>
					<tr>
						<td style="background-color:#999;">Deployment:</td>
						<td><select id="deployment" name="deployment" style="text-align:center;width:80%;">
						<?php if($cluster['deployment'] == '1') { ?>
							<option value="1" selected>Load-balanced</option> 
							<option value="2">Resource based</option>
						<?php } else { ?>
							<option value="1">Load-balanced</option> 
							<option value="2" selected>Resource based</option>
						<?php } ?>
							</select>
						</td>
					</tr>
					<tr>
						<td style="background-color:#999;">Last Updated:</td>
						<td><?php echo date('m/j/Y @ g:i:s A', $cluster['last_updated']); ?></td>
					</tr>
				</table>
				<br />
				<br />
				<center><button type="submit" name="editcluster" id="editcluster" class="stylish-button">EDIT CLUSTER</button><br /></center>
				</form>
				<br />
				<hr />
				<br />
				<table>
					<tr>
						<td style="background-color:#999;">TOGGLE CLUSTER:</td>
						<td style="padding:10px;">
						<form id="togglecluster" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
							<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
							<input type="hidden" name="id" value="<?php echo htmlspecialchars($cluster_id); ?>">
						<?php if($cluster['status'] == "1") { ?>
							<button type="submit" class="stylish-button" name="disable_cluster">DISABLE</button>
						<?php } else { ?>
							<button type="submit" class="stylish-button" name="enable_cluster">ENABLE</button>
						<?php } ?>
						</form>
						</td>
					</tr>					
				</table>
				<?php if($cluster['status'] == "0") { ?>
				<br />
				<hr />
				<br />
				<table>
					<tr>
						<td style="background-color:#999;">DELETE CLUSTER:</td>
						<td style="padding:10px;">
						<form id="delete_cluster" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
						<label class="checkbox-container" style="padding:5px;">
							<input type="checkbox" name="confirm" style="padding:5px;">
							<span class="checkmark"></span>
						</label>
						Confirm
						</td>
						<td>
						<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
						<input type="hidden" name="id" value="<?php echo htmlspecialchars($cluster_id); ?>">
						<button type="submit" name="delete_cluster" id="delete_cluster" class="stylish-button" style="background-color:red;">DELETE</button>
						</form>
						</td>
					</tr>					
				</table>
				<?php } ?>
			</div>
<?php
} else {
	error_log("Error finding cluster.");
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
			if(checkbox) { // Check if checkbox exists
				inputField.readOnly =!checkbox.checked;
			} else {
				console.error("Checkbox not found:", checkboxId);
			}
		}
		
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
			if(event.target == modal) {
				modal.style.display = "none";
			}
		}
	</script>
	<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
	<script src="assets/filtertable.js"></script>
</body>
</html>