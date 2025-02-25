<?PHP
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php"); 
	exit; 
} else {
	define('AmAllowed', TRUE);
	require_once('config.php');
	require_once('functions.php');
	if("0.2" !== KONTROLVM_VERSION) {
		$error = "KontrolVM incorrect version.";
	} else {
		try {
			$db = new PDO("sqlite:$db_file_path");
			$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

			// SQL statement to alter the table
			$sql = "
				ALTER TABLE staff DROP COLUMN staff_salt;
				
				CREATE TABLE IF NOT EXISTS settings (
					setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
					setting_name TEXT NOT NULL,
					setting_value TEXT NOT NULL
				);
				
				CREATE TABLE IF NOT EXISTS disks (
					disk_id INTEGER PRIMARY KEY AUTOINCREMENT,
					disk_name TEXT NOT NULL,
					disk_size INTEGER,
					vm_id INTEGER,
					node_id INTEGER,
					last_updated DATETIME
				);
				
				CREATE TABLE IF NOT EXISTS logs (
					log_id INTEGER PRIMARY KEY AUTOINCREMENT,
					log_message TEXT NOT NULL,
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP
				);
				CREATE TABLE IF NOT EXISTS backups (
					backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
					backup_name TEXT NOT NULL,
					backup_size INTEGER,
					vm_id INTEGER,
					node_id INTEGER,
					created_at DATETIME
				);
				";

			$db->exec($sql);

			$success = "Database updates have been applied.";
		} catch (PDOException $e) {
			$error = "Error updating tables: ". $e->getMessage();
		}

		$db = null;
	}
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
			<h2 style="color:red;">Update Fail</h2>
			<br />
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<?php if (isset($success)) { ?>
			<h2 style="color:green;">Update Success</h2>
			<br />
			<div><?php echo $success; ?></div> 
			<p>
			</p>
		<?php } ?>
		<br /><br />
		<p style="text-align:center;font-size:0.9em;">Powered by <a href="https://github.com/KuJoe/kontrolvm" target="_blank">KontrolVM</a></p>
	</div>
</body>
</html>