<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php"); 
	exit; 
} else {
	if (isset($_GET['s']) AND $_GET['s'] == '1') {
		$success = "ISO added successfully.";
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
		$friendlyname = $_POST["friendlyname"];
		$download = $_POST["download"];
		$result = addISOs($download, $friendlyname);
		if($result === true) {
			header("Location: isos.php?s=1");
		} else {
			$error = "ISO add failed: ".$result;
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
$isos = getISOs();
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
			<?php if (in_array($myrole, ['2', '9'])) { ?> <li><a href="clusters.php">Infrastructure</a></li> <?php } ?>
			<?php if (in_array($myrole, ['1', '9'])) { ?> <li><a href="users.php">Users</a></li> <?php } ?>
			<li><a class="active" href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<ul class="submenu">
		<li><a href="settings.php">General</a></li>
		<li><a class="active" href="isos.php">ISOs</a></li>
		<li><a href="ipv4.php">IPv4 Addresses</a></li>
		<li><a href="ipv6.php">IPv6 Addresses</a></li>
		<li><a href="logs.php">Logs</a></li>
	</ul>
	<div class="container">
		<p style="float:right;"><button id="addBtn" class="stylish-button"><i class="fa-solid fa-square-plus"></i> ADD ISO</button></p>
		<div id="addModal" class="modal">
			<div class="modal-content">
				<span class="close">&times;</span>
				<h2>Add New ISO</h2>
				<br />
				<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post"> 
					<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
					<label for="friendlyname">OS Name:</label>
					<input type="text" id="friendlyname" name="friendlyname" required><br><br>
					<label for="download">Download URL:</label>
					<input type="text" id="download" name="download" required><br><br>
					<center><button type="submit" class="stylish-button"><i class="fa-solid fa-square-plus"></i> ADD ISO</button></center>
				</form>
			</div>
		</div>
		<h1>ISOs</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="table-container" style="max-width:1500px;">
		<input type="text" id="serverInput" oninput="filterServerTable()" placeholder="Search ISOs">
		<table id="server_table">
			<thead>
				<tr>
					<th>OS</th>
					<th>File</th>
					<th>Status</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody>
			<?php
				foreach ($isos as $iso) {
					$template_id = $iso['template_id'];
					echo '<tr>';
					echo "<td class='tname'>" . $iso['friendlyname'] . "</td>";
					echo "<td style='font-size:small;'>" . $iso['filename'] . "</td>";
					echo "<td><span class='ticon' style='padding-right:4px;'>Status: </span>";
					if ($iso['status'] == "1") {
						echo "<img src='assets/1.png' alt='Enabled'>";
					} else {
						echo "<img src='assets/0.png' alt='Disabled'>";
					}
					echo "</td>";
					echo "<td>N/A</td>";
					echo '</tr>';
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