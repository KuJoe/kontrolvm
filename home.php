<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
if (isset($_SESSION['mfa_required']) && $_SESSION['mfa_required']) {
	header("Location: logout.php");
	exit;
}
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
	if(isset($_GET['s'])) {
		if ($_GET['s'] == '99') {
			$error = "Account does not access to fuction.";
		}
	}
}
$token = getCSRFToken();
$last_run_time = getLastRunTime('updateNodes.php');
$script_name = 'dbBackup.php';
$last_backup = getLastRunTime($script_name); 
if (!$last_backup || time() - $last_backup >= 86400) {
	include($script_name);
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
			<li><a class="active" href="index.php">Dashboard</a></li>
			<?php if (in_array($myrole, ['2', '9'])) { ?> <li><a href="clusters.php">Infrastructure</a></li> <?php } ?>
			<?php if (in_array($myrole, ['1', '9'])) { ?> <li><a href="users.php">Users</a></li> <?php } ?>
			<li><a href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<div class="container">
		<h1>Cluster Overview</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="grid">
			<div class="card">
				<h2>Nodes</h2>
				<div class="value"><?php echo getTotalNodes(); ?></div> 
			</div>
			<div class="card">
				<h2>VMs</h2>
				<div class="value"><?php echo getTotalVMs(); ?></div> 
			</div>
			<div class="card">
				<h2>CPU Cores</h2>
				<div class="value"><?php echo getTotalCPU(); ?></div> 
			</div>
			<div class="card">
				<h2>Memory</h2>
				<div class="value"><?php echo getTotalRAM(); ?>GB</div> 
			</div>
			<div class="card">
				<h2>Storage</h2>
				<div class="value"><?php echo getTotalDisk(); ?>GB</div> 
			</div>
		</div>
		<br />
		<p style="text-align:center;font-size:12px;">Last refresh: <?php echo date('m/j/Y @ g:i:s A',$last_run_time); ?></p>
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
	</script>
	<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</body>
</html>