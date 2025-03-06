<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
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
}
if($bgupdate == true) {
	$bgustate = " checked";
} else {
	$bgustate = "";
}
if($smtp_tls == true) {
	$smtp_tls = " checked";
} else {
	$smtp_tls = "";
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
			<?php if(in_array($myrole, ['2', '9'])) { ?> <li><a href="clusters.php">Infrastructure</a></li> <?php } ?>
			<?php if(in_array($myrole, ['1', '9'])) { ?> <li><a href="users.php">Users</a></li> <?php } ?>
			<li><a class="active" href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<ul class="submenu">
		<li><a class="active" href="settings.php">General</a></li>
		<li><a href="isos.php">ISOs</a></li>
		<li><a href="ipv4.php">IPv4 Addresses</a></li>
		<li><a href="ipv6.php">IPv6 Addresses</a></li>
		<li><a href="logs.php">Logs</a></li>
	</ul>
	<div class="container">
		<h1>Settings</h1>
		<p>These are the current settings inside the config.php file, eventually most will be moved into the database.<br /><br /></p>
		<h2>Core</h2><br />
		<div class="form-group" style="width:200px;">
			<label for="database">Database:</label>
			<input type="text" id="database" name="database" value="<?php echo htmlspecialchars($db_file_path); ?>" readonly> 
		</div>
		<div class="form-group" style="width:200px;">
			<label for="sshusernow">SSH Username:</label>
			<input type="text" id="sshusernow" name="sshusernow" value="<?php echo htmlspecialchars($sshusernow); ?>" readonly>
		</div>
		<div class="form-group" style="width:200px;">
			<label for="sshkeypriv">SSH Private Key:</label>
			<input type="text" id="sshkeypriv" name="sshkeypriv" value="<?php echo htmlspecialchars($sshkeypriv); ?>" readonly>
		</div>
		<div class="form-group" style="width:200px;">
			<label for="sshkeypub">SSH Public Key:</label>
			<input type="text" id="sshkeypub" name="sshkeypub" value="<?php echo htmlspecialchars($sshkeypub); ?>" readonly>
		</div>
		<div class="form-group" style="width:200px;">
			<label for="cryptkey">Cryptography Key:</label>
			<input type="password" id="cryptkey" name="cryptkey" value="<?php echo htmlspecialchars($cryptkey); ?>" readonly>
		</div>
		<div class="form-group" style="width:210px;">
			<label for="bgupdate" style="float:left;">Background Updates: </label>
			<label class="checkbox-container" style="float:right;">
				<input type="checkbox" name="bgupdate"<?php echo $bgustate; ?> disabled>
				<span class="checkmark"></span>
			</label>
		</div>
		<br />
		<br />
		<br />
		<hr />
		<br />
		<h2>SMTP</h2><br />
		<div class="form-group" style="width:200px;">
			<label for="smtp_server">SMTP Server:</label>
			<input type="text" id="smtp_server" name="smtp_server" value="<?php echo htmlspecialchars($smtp_server); ?>" readonly>
		</div>
		<div class="form-group" style="width:200px;">
			<label for="smtp_port">SMTP Port:</label>
			<input type="text" id="smtp_port" name="smtp_port" value="<?php echo htmlspecialchars($smtp_port); ?>" readonly>
		</div>
		<div class="form-group" style="width:200px;">
			<label for="smtp_user">SMTP User:</label>
			<input type="text" id="smtp_user" name="smtp_user" value="<?php echo htmlspecialchars($smtp_user); ?>" readonly>
		</div>
		<div class="form-group" style="width:200px;">
			<label for="smtp_password">SMTP Password:</label>
			<input type="password" id="smtp_password" name="smtp_password" value="<?php echo htmlspecialchars($smtp_password); ?>" readonly>
		</div>
		<div class="form-group" style="width:150px;">
			<label for="smtp_tls" style="float:left;">TLS Enabled: </label>
			<label class="checkbox-container" style="float:right;">
				<input type="checkbox" name="smtp_tls"<?php echo $tlsstate; ?> disabled>
				<span class="checkmark"></span>
			</label>
		</div>
		<br />
		<br />
		<div class="form-group" style="width:200px;">
			<label for="smtp_sender">SMTP Sender:</label>
			<input type="text" id="smtp_sender" name="smtp_sender" value="<?php echo htmlspecialchars($smtp_sender); ?>" readonly>
		</div>
		<br />
		<hr />
		<br />
		<h2>Cloudflare Turnstile</h2><br />
		<div class="form-group" style="width:200px;">
			<label for="sitekey">Site Key:</label>
			<input type="text" id="sitekey" name="sitekey" value="<?php echo htmlspecialchars($sitekey); ?>" readonly>
		</div>
		<div class="form-group" style="width:200px;">
			<label for="secretkey">Secret Key:</label>
			<input type="password" id="secretkey" name="secretkey" value="<?php echo htmlspecialchars($secretkey); ?>" readonly>
		</div>
	</div>
	<?php include('footer.php'); ?>
	<script>
		// JavaScript code to handle theme switching (from previous responses)
		const themeToggle = document.getElementById('theme-toggle');
		const body = document.body;
	
		// Load the user's preferred theme from localStorage
		const savedTheme = localStorage.getItem('theme');
		if(savedTheme === 'dark') {
			body.classList.add('dark-mode');
			themeToggle.checked = true; 
		}
	
		themeToggle.addEventListener('change', () => {
			if(themeToggle.checked) {
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