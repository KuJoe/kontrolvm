<?PHP
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php"); 
	exit; 
}
function alterTableIfExists($conn, $alterQuery) {
    try {
        $conn->exec($alterQuery);
    } catch (Exception $e) {
        // Check if the error indicates the change already exists
        if (strpos($e->getMessage(), 'duplicate column name') !== false ||
            strpos($e->getMessage(), 'duplicate table column') !== false ||
            strpos($e->getMessage(), 'duplicate column') !== false ||
            strpos($e->getMessage(), 'duplicate key name') !== false ||
            strpos($e->getMessage(), 'duplicate index name') !== false ||
            strpos($e->getMessage(), 'no such column') !== false ||
            strpos($e->getMessage(), 'already exists') !== false) {
            //echo "ALTER TABLE already exists or is a duplicate. Ignoring.\n";
			return true;
        } else {
            throw $e;
        }
    }
}
function updateDB() {
	try {
		include('config.php');
		$conn = new PDO("sqlite:$db_file_path");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		// SQL statement to alter the table
		$dropColumns = [
			'staff' => 'staff_salt', 'nodes' => 'loc', 'vms' => 'loc', 'clusters' => 'loc', 'ipv4' => 'loc', 'ipv6' => 'loc', 'ipv4' => 'reserved', 'ipv6' => 'reserved' ];

		$addColumns = [
			'clusters' => 'deployment INTEGER', 'nodes' => 'cluster INTEGER', 'vms' => 'cluster INTEGER', 'ipv4' => 'cluster INTEGER', 'ipv6' => 'cluster INTEGER', 'staff' => 'staff_role INTEGER' ];

		$renameColumns = [
			'clusters' => ['clusterid', 'cluster_id'], 'last_run' => ['id', 'run_id'], 'ostemplates' => ['templateid', 'template_id'], 'ipv4' => ['ipid', 'ip_id'], 'ipv6' => ['ipid', 'ip_id'] ];

		// Drop Columns
		foreach ($dropColumns as $table => $column) {
			$alterQuery = "ALTER TABLE {$table} DROP COLUMN {$column}";
			alterTableIfExists($conn, $alterQuery);
		}

		// Add Columns
		foreach ($addColumns as $table => $columnDefinition) {
			$alterQuery = "ALTER TABLE {$table} ADD COLUMN {$columnDefinition}";
			alterTableIfExists($conn, $alterQuery);
		}

		// Rename Columns
		foreach ($renameColumns as $table => $columns) {
			$oldColumn = $columns[0];
			$newColumn = $columns[1];
			$alterQuery = "ALTER TABLE {$table} RENAME COLUMN {$oldColumn} TO {$newColumn}";
			alterTableIfExists($conn, $alterQuery);
		}
		
		// Create new tables if they don't exist.
		$sql = "CREATE TABLE IF NOT EXISTS settings (setting_id INTEGER PRIMARY KEY AUTOINCREMENT, setting_name TEXT NOT NULL, setting_value TEXT NOT NULL);
				CREATE TABLE IF NOT EXISTS disks (disk_id INTEGER PRIMARY KEY AUTOINCREMENT, disk_name TEXT NOT NULL, disk_size INTEGER, vm_id INTEGER, node_id INTEGER, last_updated DATETIME);
				CREATE TABLE IF NOT EXISTS logs (log_id INTEGER PRIMARY KEY AUTOINCREMENT, log_message TEXT NOT NULL, straff_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);			
				CREATE TABLE IF NOT EXISTS backups (backup_id INTEGER PRIMARY KEY AUTOINCREMENT, backup_name TEXT NOT NULL, backup_size INTEGER, vm_id INTEGER, node_id INTEGER, status INTEGER, created_at DATETIME);
				CREATE TABLE IF NOT EXISTS nics (nic_id INTEGER PRIMARY KEY AUTOINCREMENT, nic_name TEXT NOT NULL, mac_address TEXT, vm_id INTEGER, node_id INTEGER, last_updated DATETIME);
				CREATE TABLE IF NOT EXISTS networks (net_id INTEGER PRIMARY KEY AUTOINCREMENT, net_name TEXT NOT NULL, node_id INTEGER, last_updated DATETIME);
				";
		$conn->exec($sql);
		return true;
	} catch (PDOException $e) {
		return "Error updating tables: ". $e->getMessage();
	}

	$conn = null;
}
$resultDB = updateDB();
if($resultDB === true) {
	$success = "✅";
} else {
	$error = $resultDB;
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
			<h2 style="color:red;">Update Failed</h2>
			<br />
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<?php if(isset($success)) { ?>
			<h2 style="color:green;">Update Success</h2>
			<br />
			<div style="text-align:center;"><?php echo $success; ?></div> 
			<p>
			</p>
		<?php } ?>
		<br /><br />
		<p style="text-align:center;font-size:0.9em;">Powered by <a href="https://github.com/KuJoe/kontrolvm" target="_blank">KontrolVM</a></p>
	</div>
</body>
</html>