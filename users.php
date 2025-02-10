<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php"); 
	exit; 
} else {
	if (isset($_GET['s'])) {
		if ($_GET['s'] == '1') {
			$success = "User created successfully.";
		} elseif ($_GET['s'] == '2') {
			$success = "User deleted successfully.";
		}
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
		$username = $_POST["username"];
		$email = $_POST["email"];
		$result = createUser($username,$email);
		if ($variable!== false) {
			$success = "User created successfully with this temporary password: ".$result;
			$_GET['state'] = "all";
		} else {
			$error = "User create failed: ".$result;
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
	$users = getUserList('all');
} else {
	$users = getUserList('1');
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
			<li><a href="nodes.php">Nodes</a></li>
			<li><a href="vms.php">VMs</a></li>
			<li><a href="users.php">Users</a></li>
			<li><a href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo $_SESSION["username"]; ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<div class="container" style="min-width:350px;max-width:1500px;">
		<p style="float:right;"><button id="addBtn" class="stylish-button"><i class="fa-solid fa-square-plus"></i> CREATE USER</button></p>
		<div id="addModal" class="modal">
			<div class="modal-content">
				<span class="close">&times;</span>
				<h2>Create New User</h2>
				<br />
				<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post"> 
					<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
					<label for="username">Username:</label>
					<input type="text" id="username" name="username" minlength="4" maxlength="30" required><br><br>
					<label for="email">E-mail Address:</label>
					<input type="text" id="email" name="email" required><br><br>
					<center><button type="submit" class="stylish-button"><i class="fa-solid fa-square-plus"></i> CREATE USER</button></center>
				</form>
			</div>
		</div>
		<h1>Users</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="table-container" style="max-width:1500px;">
		<input type="text" id="serverInput" oninput="filterServerTable()" placeholder="Search VMs">
		<table id="server_table">
			<thead>
				<tr>
					<th>Name</th>
					<th>Status</th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ($users as $user):
					$staff_id = $user['staff_id'];
					$username = $user['staff_username'];
				?>
				<tr>
				<td class="tname"><a href="account.php?id=<?php echo $staff_id; ?>"><?php echo $username; ?></a></td>
				<td>
				<?php
				if ($user['staff_active'] == "1") {
					echo "<img src='assets/1.png' alt='Active'>";
				} else {
					echo "<img src='assets/0.png' alt='Disabled'>";
				}
				?>
				</td>
				</tr>
				<?php endforeach;?>
			</tbody>
		</table>
		</div>
		<p style="text-align:center;padding:10px;font-weight:bold;"><a href="users.php?state=all">View All</a></p>
	</div>
	<?php include('footer.php'); ?>
	<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
	<script src="assets/filtertable.js"></script>
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
</body>
</html>