<?PHP
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

use phpseclib3\Crypt\EC;
require __DIR__ . '/vendor/autoload.php';

$filename = 'LOCKED';
if (file_exists($filename)) {
	die("The directory is locked. Please delete the LOCKED file if you are sure you need to run the install.php file (this might overwrite existing data in the database if it exists).");
}

if (file_exists('config.php')) {
	require_once('config.php');
} else {
	die("The config.php file does not exist. Please upload it to the same folder as this file.");
}

function addSetting($name,$value) {
	$stmt = $conn->prepare("INSERT INTO settings (setting_name, setting_value) VALUES (:setting_name, :setting_value)");
	$stmt->bindValue(':setting_name', "$name", SQLITE3_TEXT);
	$stmt->bindValue(':setting_value', "$value", SQLITE3_TEXT);
	$stmt->execute();
	return true;
}

//Generate the super user for later.
$username = "admin";
$password = substr(md5(time()), 0, 16);
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

try {
	//Create the database tables.
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$tables = [
	'nodes' => "CREATE TABLE nodes (
		node_id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT NOT NULL UNIQUE,
		ipaddr TEXT NOT NULL,
		cluster INTEGER,
		cpu_cores INTEGER,
		total_memory INTEGER, 
		disk_space INTEGER,
		sshport INTEGER,
		sshuser TEXT,
		sshkey TEXT,
		uptime TEXT,
		memused TEXT,
		disksys TEXT,
		diskclnt TEXT,
		load TEXT,
		make TEXT,
		model TEXT,
		cpu TEXT,
		vms INTEGER,
		lastvnc INTEGER,
		lastws INTEGER,
		lastvm INTEGER,
		os_version TEXT,
		kernel_version TEXT,
		libvirt_version TEXT,
		status INTEGER,
		last_updated DATETIME
	)",
	'last_run' => "CREATE TABLE IF NOT EXISTS last_run (
		run_id INTEGER PRIMARY KEY AUTOINCREMENT,
		script_name TEXT NOT NULL,
		last_run_time INTEGER
	)",
	'ostemplates' => "CREATE TABLE IF NOT EXISTS ostemplates (
		template_id INTEGER PRIMARY KEY AUTOINCREMENT,
		filename TEXT NOT NULL,
		friendlyname TEXT NOT NULL,
		type TEXT NOT NULL,
		variant TEXT NOT NULL,
		status TEXT NOT NULL,
		added DATETIME
	)",
	'ipv4' => "CREATE TABLE IF NOT EXISTS ipv4 (
		ip_id INTEGER PRIMARY KEY AUTOINCREMENT,
		ipaddress TEXT NOT NULL,
		gwip TEXT NOT NULL,
		vmid INTEGER,
		node INTEGER,
		cluster INTEGER,
		notes TEXT,
		status INTEGER,
		last_updated DATETIME
	)",
	'ipv6' => "CREATE TABLE IF NOT EXISTS ipv6 (
		ip_id INTEGER PRIMARY KEY AUTOINCREMENT,
		ipaddress TEXT NOT NULL,
		gwip TEXT NOT NULL,
		vmid INTEGER,
		node INTEGER,
		cluster INTEGER,
		notes TEXT,
		status INTEGER,
		last_updated DATETIME
	)",
	'staff' => "CREATE TABLE staff (
		staff_id INTEGER PRIMARY KEY AUTOINCREMENT,
		staff_username TEXT NOT NULL DEFAULT '',
		staff_email TEXT,
		staff_password TEXT NOT NULL DEFAULT 0,
		staff_pwreset TEXT,
		staff_active INTEGER NOT NULL DEFAULT 0,
		staff_rememberme_token TEXT,
		staff_mfa TEXT,
		staff_role INTEGER,
		staff_ip TEXT,
		staff_lastlogin TEXT,
		staff_failed_logins INTEGER NOT NULL DEFAULT 0,
		staff_locked DATETIME NOT NULL DEFAULT '1970-01-01 00:00:01'
	)",
	'vms' => "CREATE TABLE vms (
		vm_id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		hostname TEXT NOT NULL,
		status INTEGER,
		protected INTEGER,
		cluster INTEGER,
		cpu_cores INTEGER,
		memory INTEGER,
		ipv4 INTEGER,
		ipv6 INTEGER,
		os_template TEXT,
		os_type TEXT,
		mac_address TEXT,
		nic INTEGER,
		iow INTEGER,
		notes TEXT,
		vncpw TEXT,
		vncport INTEGER,
		vncexpire INTEGER,
		websockify INTEGER,
		netdriver TEXT,
		network TEXT,
		diskdriver TEXT,
		bootorder TEXT,
		created_at DATETIME,
		last_updated DATETIME
	)",
	'disks' => "CREATE TABLE IF NOT EXISTS disks (
		disk_id INTEGER PRIMARY KEY AUTOINCREMENT,
		disk_name TEXT NOT NULL,
		disk_size INTEGER,
		vm_id INTEGER,
		node_id INTEGER,
		last_updated DATETIME
	)",
	'clusters' => "CREATE TABLE IF NOT EXISTS clusters (
		cluster_id INTEGER PRIMARY KEY AUTOINCREMENT,
		friendlyname TEXT NOT NULL,
		notes TEXT,
		deployment INTEGER,
		status INTEGER,
		last_updated DATETIME
	)",
	'settings' => "CREATE TABLE IF NOT EXISTS settings (
		setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
		setting_name TEXT NOT NULL,
		setting_value TEXT NOT NULL
	)",
	'logs' => "CREATE TABLE IF NOT EXISTS logs (
		log_id INTEGER PRIMARY KEY AUTOINCREMENT,
		log_message TEXT NOT NULL,
		staff_id INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)",
	'backups' => "CREATE TABLE IF NOT EXISTS backups (
		backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
		backup_name TEXT NOT NULL,
		backup_size INTEGER,
		vm_id INTEGER,
		node_id INTEGER,
		status INTEGER,
		created_at DATETIME
	)",
	'nics' => "CREATE TABLE IF NOT EXISTS nics (
		nic_id INTEGER PRIMARY KEY AUTOINCREMENT,
		nic_name TEXT NOT NULL,
		mac_address TEXT,
		vm_id INTEGER NOT NULL,
		node_id INTEGER NOT NULL,
		last_updated DATETIME
	)",
	'networks' => "CREATE TABLE IF NOT EXISTS networks (
		net_id INTEGER PRIMARY KEY AUTOINCREMENT,
		net_name TEXT NOT NULL,
		node_id INTEGER NOT NULL,
		last_updated DATETIME
	)"
	];
	foreach ($tables as $name => $sql) {
		$stmt = $conn->prepare($sql);
		$stmt->execute();
	}
	// Create Super Admin account
	$stmt = $conn->prepare("INSERT INTO staff (staff_username, staff_password, staff_active, staff_role) VALUES (:username, :password, :active, :role)");
	$stmt->bindValue(':username', "$username", SQLITE3_TEXT);
	$stmt->bindValue(':password', "$hashedPassword", SQLITE3_TEXT);
	$stmt->bindValue(':active', '1', SQLITE3_INTEGER);
	$stmt->bindValue(':role', '9', SQLITE3_INTEGER);
	$stmt->execute();
	
	//// Populate default settings
	//$setting = [
	//'bgupdate' => "true",
	//'' => "",
	//'' => "",
	//];
	//foreach ($setting as $name => $value) {
	//	addSetting($name,$value);
	//}
	
	//Create the SSH key
	$privateKey = EC::createKey('Ed25519');
	$publicKey = $privateKey->getPublicKey(); 
	$privateKeyString = $privateKey->toString('OpenSSH'); 
	$publicKeyString = $publicKey->toString('OpenSSH');
	file_put_contents($sshkeypriv, $privateKeyString);
	file_put_contents($sshkeypub, $publicKeyString);
	
	$success = "Database has been deployed and the tables have been successfully created.<br />An SSH key has been generated for internal use.";
	
} catch(PDOException $e) {
	$error = $e->getMessage();
}
$file = fopen('LOCKED', 'w');
if ($file == false) {
	$lock = "Unable to lock the directory to prevent the install.php script from being run again. Either manually create a file named <strong>LOCKED</strong> in this directory or delete the install.php to be safe.";
} else {
	$lock = "Lock file created to prevent the install.php file from being run again. You can delete the install.php file just to safe.";
	fclose($file);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>KontrolVM</title>
	<style>
		body {
			font-family: sans-serif;
			display: flex;
			justify-content: center;
			align-items: center;
			min-height: 100vh;
			background-color: #f4f4f7;
		}

		.container {
			background-color: #fff;
			padding: 40px;
			border-radius: 8px;
			box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
			max-width: 400px; 
			width: 100%;
		}

		h2 {
			text-align: center;
			margin-bottom: 20px;
		}

		.error-message {
			color: #dc3545;
			background-color: #f8d7da;
			border: 1px solid #f5c6cb;
			padding: 10px;
			margin-bottom: 15px;
			border-radius: 4px;
			text-align: center;
		}
	</style>
</head>
<body>
	<div class="container">
		<img src="assets/logo.png" alt="KontrolVM Logo" style="display:block;margin:0 auto;" />
		<br />
		<br />
		<?php if(isset($error)) { ?>
			<h2 style="color:red;">Install Fail</h2>
			<br />
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<?php if (isset($success)) { ?>
			<h2 style="color:green;">Install Success</h2>
			<br />
			<div><?php echo $success; ?></div> 
			<p>
			<br />
			The following user was created:<br />
			Username: <b><?php echo $username; ?></b><br />
			Password: <b><?php echo $password; ?></b><br />
			<i>Write these down, they will not be displayed again and cannot be recovered at this time.</i>
			<br />
			<?php echo $lock; ?>
			<br />
			<br />
			<a href="index.php">LOGIN</a>
			</p>
		<?php } ?>
		<br /><br />
		<p style="text-align:center;font-size:0.9em;">Powered by <a href="https://github.com/KuJoe/kontrolvm" target="_blank">KontrolVM</a></p>
	</div>
</body>
</html>