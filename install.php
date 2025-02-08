<?PHP
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

$filename = 'LOCKED';
if (file_exists($filename)) {
	die("The directory is locked. Please delete the LOCKED file if you are sure you need to run the install.php file (this might overwrite existing data in the database if it exists).");
}

if (file_exists('config.php')) {
	require_once('config.php');
} else {
	die("The config.php file does not exist. Please upload it to the same folder as this file.");
}
$username = "admin";
$password = substr(md5(time()), 0, 16);
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

try {
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$tables = [
	'nodes' => "CREATE TABLE nodes (
		node_id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT NOT NULL UNIQUE,
		ipaddr TEXT NOT NULL,
		cpu_cores INTEGER,
		total_memory INTEGER, 
		disk_space INTEGER,
		sshport INTEGER,
		loc TEXT,
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
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		script_name TEXT NOT NULL,
		last_run_time INTEGER
	)",
	'ostemplates' => "CREATE TABLE IF NOT EXISTS ostemplates (
		templateid INTEGER PRIMARY KEY AUTOINCREMENT,
		filename TEXT NOT NULL,
		friendlyname TEXT NOT NULL,
		type TEXT NOT NULL,
		variant TEXT NOT NULL,
		status TEXT NOT NULL,
		added DATETIME
	)",
	'ipv4' => "CREATE TABLE IF NOT EXISTS ipv4 (
		ipid INTEGER PRIMARY KEY AUTOINCREMENT,
		ipaddress TEXT NOT NULL,
		gwip TEXT NOT NULL,
		vmid INTEGER,
		reserved INTEGER,
		node INTEGER,
		loc TEXT,
		notes TEXT,
		status INTEGER,
		last_updated DATETIME
	)",
	'ipv6' => "CREATE TABLE IF NOT EXISTS ipv6 (
		ipid INTEGER PRIMARY KEY AUTOINCREMENT,
		ipaddress TEXT NOT NULL,
		gwip TEXT NOT NULL,
		vmid INTEGER,
		reserved INTEGER,
		node INTEGER,
		loc TEXT,
		notes TEXT,
		status INTEGER,
		last_updated DATETIME
	)",
	'staff' => "CREATE TABLE staff (
		staff_id INTEGER PRIMARY KEY AUTOINCREMENT,
		staff_username TEXT NOT NULL DEFAULT '',
		staff_email TEXT NOT NULL DEFAULT '',
		staff_password TEXT NOT NULL DEFAULT 0,
		staff_active INTEGER NOT NULL DEFAULT 0,
		staff_rememberme_token TEXT NOT NULL DEFAULT 0,
		staff_mfa TEXT NOT NULL DEFAULT '',
		staff_ip TEXT NOT NULL DEFAULT 0,
		staff_lastlogin TEXT NULL DEFAULT NULL,
		staff_failed_logins INTEGER NOT NULL DEFAULT 0,
		staff_locked DATETIME NOT NULL DEFAULT '1970-01-01 00:00:01'
	)",
	'vms' => "CREATE TABLE vms (
		vm_id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		hostname TEXT NOT NULL,
		ip_address TEXT,
		status INTEGER,
		protected INTEGER,
		loc TEXT,
		cpu_cores INTEGER,
		memory INTEGER, 
		disk1 TEXT,
		disk_space1 INTEGER,
		disk2 TEXT,
		disk_space2 INTEGER,
		disk3 TEXT,
		disk_space3 INTEGER,
		disk4 TEXT,
		disk_space4 INTEGER,
		ipv4 INTEGER,
		ipv6 INTEGER,
		mac_address TEXT,
		os_template TEXT,
		os_type TEXT,
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
	'clusters' => "CREATE TABLE IF NOT EXISTS clusters (
		clusterid INTEGER PRIMARY KEY AUTOINCREMENT,
		loc TEXT NOT NULL,
		friendlyname TEXT NOT NULL,
		notes TEXT,
		status INTEGER,
		last_updated DATETIME
	)"
	];
	foreach ($tables as $name => $sql) {
		$stmt = $conn->prepare($sql);
		$stmt->execute();
	}
	$stmt = $conn->prepare("INSERT INTO staff (staff_username, staff_password, staff_active) VALUES (:username, :password, :active)");
	$stmt->bindValue(':username', "$username", SQLITE3_TEXT);
	$stmt->bindValue(':password', "$hashedPassword", SQLITE3_TEXT);
	$stmt->bindValue(':active', '1', SQLITE3_INTEGER);
	$stmt->execute();
	$success = $db_file_path." has been deployed and the tables have been successfully created.";
	
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
			Username: <?php echo $username; ?><br />
			Password: <?php echo $password; ?><br />
			<br />
			<?php echo $lock; ?>
			</p>
		<?php } ?>
		<br /><br />
		<p style="text-align:center;font-size:0.9em;">Powered by <a href="https://github.com/KuJoe/kontrolvm" target="_blank">KontrolVM</a></p>
	</div>
</body>
</html>