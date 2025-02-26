<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php"); 
	exit; 
} else {
	if (isset($_GET['s']) AND $_GET['s'] == '1') {
		$success = "IP added successfully.";
	}
	if (isset($_GET['s']) AND $_GET['s'] == '2') {
		$success = "IP deleted successfully.";
	}
	if (isset($_GET['s']) AND $_GET['s'] == '3') {
		$success = "IP reserved successfully.";
	}
	if (isset($_GET['s']) AND $_GET['s'] == '4') {
		$success = "IP unreserved successfully.";
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
}
if ($_SERVER["REQUEST_METHOD"] == "POST") {
	$token = $_POST["csrf_token"];
	if (validateCSRFToken($token)) {
		if (isset($_POST['add_ip'])) {
			$ipaddress = $_POST["ipaddress"];
			if (strlen($ipaddress) === 19) {
				$gwip = $_POST["gwip"];
				$cluster = $_POST["cluster"];
				$result = addIPs($ipaddress, $gwip, $cluster);
				if($result === true) {
					header("Location: ipv6.php?s=1");
				} else {
					$error = "IP add failed: ".$result;
				}
			} else {
				$error = "IPv6 subnet needs to be 19 characters in this format: <b>XXXX:XXXX:XXXX:XXXX</b>";
			}
		}
		if (isset($_POST['delete_ip'])) {
			$idToChange = $_POST['ip_id'];
			$ipToChange = $_POST['ipaddress'];
			$result = deleteIP($idToChange,$ipToChange);
			if($result === true) {
				header("Location: ipv6.php?s=2");
			} else {
				$error = "IP deletion failed: ".$result;
			}
		}
		if (isset($_POST['reserve_ip'])) {
			$idToChange = $_POST['ip_id'];
			$ipToChange = $_POST['ipaddress'];
			$result = reserveIP($idToChange,$ipToChange);
			if($result === true) {
				header("Location: ipv6.php?s=3");
			} else {
				$error = "IP reservation failed: ".$result;
			}
		}
		if (isset($_POST['unreserve_ip'])) {
			$idToChange = $_POST['ip_id'];
			$ipToChange = $_POST['ipaddress'];
			$result = unreserveIP($idToChange,$ipToChange);
			if($result === true) {
				header("Location: ipv6.php?s=4");
			} else {
				$error = "IP unreserve failed: ".$result;
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
$ips = getIPs('v6');
$clusters = getClusters('1');
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
			<li><a href="clusters.php">Infrastructure</a></li>
			<li><a href="users.php">Users</a></li>
			<li><a class="active" href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<ul class="submenu">
		<li><a href="settings.php">General</a></li>
		<li><a href="isos.php">ISOs</a></li>
		<li><a href="ipv4.php">IPv4 Addresses</a></li>
		<li><a class="active" href="ipv6.php">IPv6 Addresses</a></li>
		<li><a href="logs.php">Logs</a></li>
	</ul>
	<div class="container">
		<p style="float:right;"><button id="addBtn" class="stylish-button"><i class="fa-solid fa-square-plus"></i> ADD /64</button></p>
		<div id="addModal" class="modal">
			<div class="modal-content">
				<span class="close">&times;</span>
				<h2>Add New /64 Subnet</h2>
				<br />
				<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post"> 
					<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
					<label for="ipaddress">IP Address (/64 subnet):</label>
					<input type="text" id="ipaddress" name="ipaddress" placeholder="XXXX:XXXX:XXXX:XXXX" maxlength="19" required><br><br>
					<label for="gwip">Gateway:</label>
					<input type="text" id="gwip" name="gwip" required><br><br>
					<label for="cluster">Cluster:</label>
					<select name="cluster" style="text-align:center;">
					<?php foreach ($clusters as $cluster):?>
							<option value="<?php echo htmlspecialchars($cluster['cluster_id']);?>">
					<?php echo htmlspecialchars($cluster['friendlyname']);?> 
						</option>
					<?php endforeach;?>
					</select><br /><br />
					<center><button type="submit" class="stylish-button" name="add_ip"><i class="fa-solid fa-square-plus"></i> ADD /64</button></center>
				</form>
			</div>
		</div>
		<h1>IPv6 Addresses</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="table-container" style="max-width:1500px;">
		<input type="text" id="serverInput" oninput="filterServerTable()" placeholder="Search IPs">
		<table id="server_table">
			<thead>
				<tr>
					<th>IP Address</th>
					<th>VM</th>
					<th>Gateway</th>
					<th>Cluster</th>
					<th>Node</th>
					<th>Available</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody>
			<?php
				foreach ($ips as $ip) {
					$ip_id = $ip['ip_id'];
					echo '<tr>';
					echo "<td class='tname'>" . $ip['ipaddress'] . "</td>";
					echo "<td style='font-size:small;'>" . $ip['vmid'] . "</td>";
					echo "<td style='font-size:small;'>" . $ip['gwip'] . "</td>";
					echo "<td style='font-size:small;'>" . getClusterName($ip['cluster']) . "</td>";
					echo "<td style='font-size:small;'>" . getNodeName($ip['node']) . "</td>";
					echo "<td><span class='ticon' style='padding-right:4px;'>Available: </span>";
					if ($ip['reserved'] == "0") {
						echo "<img src='assets/1.png' alt='Available'>";
					} else {
						echo "<img src='assets/0.png' alt='Unavailable'>";
					}
					echo "</td>";
					echo "<td>";
					echo '<form action="'.htmlspecialchars($_SERVER["PHP_SELF"]).'" method="post"> 
							<input type="hidden" name="csrf_token" value="'.$csrfToken.'">
							<input type="hidden" name="ip_id" value="'.$ip_id.'">
							<input type="hidden" name="ipaddress" value="'.$ip['ipaddress'].'">
							<button type="submit" class="stylish-button" name="delete_ip">Delete</button>
						  </form>';
					echo '<br /><form action="'.htmlspecialchars($_SERVER["PHP_SELF"]).'" method="post"> 
							<input type="hidden" name="csrf_token" value="'.$csrfToken.'">
							<input type="hidden" name="ip_id" value="'.$ip_id.'">
							<input type="hidden" name="ipaddress" value="'.$ip['ipaddress'].'">';
					if ($ip['reserved'] == "1") {
						echo '<button type="submit" class="stylish-button" name="unreserve_ip">Enable</button>';
					} else {
						echo '<button type="submit" class="stylish-button" name="reserve_ip">Disabled</button>';
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