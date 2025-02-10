<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

define('AmAllowed', TRUE);
session_start();
require_once('config.php');
require_once('functions.php');
$remote_addr = getRealUserIp();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
	$errorMessage = "";
	if (isset($_POST['username']) && isset($_POST['password'])) {
		if(isset($secretkey)) {
			$cf_url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
			$token = $_POST['cf-turnstile-response'];
			$data = array(
				"secret" => $secretkey,
				"response" => $token,
				"remoteip" => $remote_addr
			);
			$curl = curl_init();
			curl_setopt($curl, CURLOPT_URL, $cf_url);
			curl_setopt($curl, CURLOPT_POST, true);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
			$response = curl_exec($curl);
			if (curl_errno($curl)) {
				$error_message = curl_error($curl);
				error_log("Error with CAPTCHA: " . $error_message);
				curl_close($curl);
				header("Location: index.php?e=1");
			}else{
				$response = json_decode($response,true);
				if ($response['error-codes'] && count($response['error-codes']) > 0){
					error_log("Cloudflare Turnstile check failed.");
					curl_close($curl);
					header("Location: index.php?e=1");
				}
			}
			curl_close($curl);
		}
		$username = $_POST["username"];
		$password = $_POST['password'];
		try {
			$conn = new PDO("sqlite:$db_file_path");
			$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			$sql = "SELECT * FROM staff WHERE staff_username = :username";
			$stmt = $conn->prepare($sql);
			$stmt->bindValue(':username', "$username", SQLITE3_TEXT);
			$stmt->execute();
			$user = $stmt->fetch(PDO::FETCH_ASSOC);
			if($user) {
				$staff_id = $user['staff_id'];
				$chkActive = checkActive($staff_id);
				$chkLocked = checkLockedOut($staff_id);
				if($chkLocked == false AND $chkActive == true) {
					if(password_verify($password, $user['staff_password'])) {
						$_SESSION["loggedin"] = true; 
						$_SESSION["username"] = $username;
						$_SESSION['staff_id'] = $staff_id;
						$staff_lastlogin = time();
						$stmt = $conn->prepare("UPDATE staff SET staff_ip =:staff_ip, staff_lastlogin =:staff_lastlogin, staff_failed_logins =:staff_failed_logins WHERE staff_id =:staff_id");
						$stmt->bindValue(':staff_ip', "$remote_addr", SQLITE3_TEXT);
						$stmt->bindValue(':staff_lastlogin', "$staff_lastlogin", SQLITE3_TEXT);
						$stmt->bindValue(':staff_failed_logins', '0', SQLITE3_INTEGER);
						$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
						$stmt->execute();
						header("refresh:3;url=home.php"); 
					} else {
						$sql = "UPDATE staff SET staff_failed_logins = staff_failed_logins + 1 WHERE staff_id =:staff_id";
						$stmt = $conn->prepare($sql);
						$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
						$stmt->execute();
						$stmt = $conn->prepare("SELECT staff_failed_logins FROM staff WHERE staff_id = $staff_id");
						$stmt->execute();
						$chkFailed = $stmt->fetchColumn();
						if($chkFailed > "3") {
							$rightNow = date('Y-m-d H:i:s');
							$locked_datetime = DateTime::createFromFormat('Y-m-d H:i:s', $rightNow);
							$locked_datetime->modify('+15 minutes');
							$lockedTime = $locked_datetime->format('Y-m-d H:i:s');
							$sql = "UPDATE staff SET staff_locked =:staff_locked, staff_failed_logins =:staff_failed_logins WHERE staff_id =:staff_id";
							$stmt = $conn->prepare($sql);
							$stmt->bindValue(':staff_locked', "$lockedTime", SQLITE3_TEXT);
							$stmt->bindValue(':staff_failed_logins', '0', SQLITE3_INTEGER);
							$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
							$stmt->execute();
						}
						header("Location: index.php?e=0");
					}
				} else {
					header("Location: index.php?e=2");
				}
			} else {
				header("Location: index.php?e=0");
			}
		} catch (PDOException $e) {
			echo "Error: " . $e->getMessage();
		}
		$stmt = null;
	}	
} else {
	header("refresh:3;url=index.php");
	exit;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Authenticating...</title>
	<style>
		body {
			font-family: sans-serif;
			display: flex;
			justify-content: center;
			align-items: center;
			min-height: 100vh;
			background-color: #f4f4f7;
		}

		.logout-container {
			background-color: #fff;
			padding: 30px;
			border-radius: 8px;
			box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
			text-align: center;
		}

		h1 {
			color: #333;
		}

		p {
			margin-top: 15px;
			color: #666;
		}

		.loader {
			border: 8px solid #f3f3f3; 
			border-radius: 50%;
			border-top: 8px solid #3498db; 
			width: 40px;
			height: 40px;
			animation: spin 2s linear infinite;
			margin: 20px auto;
		}

		@keyframes spin {
			0% { transform: rotate(0deg); }
			100% { transform: rotate(360deg); }
		}
	</style>
</head>
<body>
	<div class="logout-container">
		<h1>Authenticating account...</h1>
		<p>Please wait.</p>
		<div class="loader"></div> 
	</div>
</body>
</html>