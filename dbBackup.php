<?php

require_once('config.php');
$backup_file_path = $db_file_path.".bak"; 

try {
	$conn = new SQLite3($db_file_path, SQLITE3_OPEN_READONLY);
	$backup_db = new SQLite3($backup_file_path);
	$result = $conn->backup($backup_db);
	if($result) {
		updateLastRunTime('dbBackup.php');
		return;
	} else {
		error_log("Error creating DB backup: ". $conn->lastErrorMsg());
		return;
	}
	$conn->close();
	$backup_db->close();
} catch (Exception $e) {
	error_log("Error creating DB backup: ". $e->getMessage());
	return;
}

?>