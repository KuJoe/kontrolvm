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
	$loggedin_id = $_SESSION['staff_id'];
	$chkActive = checkActive($loggedin_id);
	$chkLocked = checkLockedOut($loggedin_id);
	if($chkLocked == true OR $chkActive == false) {
		header("Location: logout.php");
		exit;
	}
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
			<li><a class="active" href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<ul class="submenu">
		<li><a class="active" href="settings.php">General</a></li>
		<li><a href="clusters.php">Clusters</a></li>
		<li><a href="isos.php">ISOs</a></li>
		<li><a href="ipv4.php">IPv4 Addresses</a></li>
		<li><a href="ipv6.php">IPv6 Addresses</a></li>
	</ul>
	<div class="container">
		<h1>Settings</h1>

		<form action="#" method="post"> 

			<h2>General</h2>
			<div class="form-group">
				<label for="hostname">Hostname:</label>
				<input type="text" id="hostname" name="hostname" value="kvm-cluster-01" disabled>
			</div>
			<div class="form-group">
				<label for="timezone">Timezone:</label>
				<select id="timezone" name="timezone" disabled>
					<option value="UTC">UTC</option>
					<option value="EST" selected>EST</option> 
					<option value="PST">PST</option>
					</select>
			</div>

			<h2>Network</h2>
			<div class="form-group">
				<label for="dns-server">DNS Server:</label>
				<input type="text" id="dns-server" name="dns-server" value="8.8.8.8" disabled>
			</div>
			<div class="form-group">
				<label for="ntp-server">NTP Server:</label>
				<input type="text" id="ntp-server" name="ntp-server" value="time.google.com" disabled>
			</div>

			<h2>Security</h2>
			<div class="form-group">
				<label for="password">SSH Password:</label>
				<input type="password" id="password" name="password" value="12345" disabled>
			</div>
			<div class="form-group">
				<label for="ssh-port">SSH Port:</label>
				<input type="number" id="ssh-port" name="ssh-port" value="22" disabled>
			</div>

			<button type="submit" class="stylish-button">Save Changes</button>
		</form>
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
</body>
</html>