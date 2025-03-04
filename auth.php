<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

define('AmAllowed', TRUE);
session_start();
require_once('config.php');
require_once('functions.php');
$remote_addr = getRealUserIp();

if($_SERVER["REQUEST_METHOD"] == "POST") {
	$errorMessage = "";
	if(isset($_POST['username']) && isset($_POST['password'])) {
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
			if(curl_errno($curl)) {
				$error_message = curl_error($curl);
				error_log("Error with CAPTCHA: " . $error_message);
				curl_close($curl);
				header("Location: index.php?e=1");
			}else{
				$response = json_decode($response,true);
				if($response['error-codes'] && count($response['error-codes']) > 0){
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
				$staff_role = $user['staff_role'];
				$chkActive = checkActive($staff_id);
				$chkLocked = checkLockedOut($staff_id);
				if($chkLocked == false AND $chkActive == true) {
					if(password_verify($password, $user['staff_password'])) {
						$_SESSION["username"] = $username;
						$_SESSION['staff_id'] = $staff_id;
						$_SESSION['staff_role'] = $staff_role;
						$staff_lastlogin = time();
						$stmt = $conn->prepare("UPDATE staff SET staff_ip =:staff_ip, staff_lastlogin =:staff_lastlogin, staff_failed_logins =:staff_failed_logins WHERE staff_id =:staff_id");
						$stmt->bindValue(':staff_ip', "$remote_addr", SQLITE3_TEXT);
						$stmt->bindValue(':staff_lastlogin', "$staff_lastlogin", SQLITE3_TEXT);
						$stmt->bindValue(':staff_failed_logins', '0', SQLITE3_INTEGER);
						$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
						$stmt->execute();
						if(isset($user['staff_mfa'])) {
							$_SESSION['mfa_required'] = true;
							header("Location: ". $_SERVER["PHP_SELF"]);
							exit;
						} else {
							$_SESSION["loggedin"] = true;
							header("Location: home.php");
						}
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
	} elseif(isset($_POST["otp"])) {
		$staffid = (int)$_POST["staff_id"];
		$otp = (int)$_POST["otp"];
		if(verifyMFA($staffid,$otp)) {
			unset($_SESSION['mfa_required']);
			$_SESSION["loggedin"] = true;
			header("Location: home.php");
		} else {
			session_destroy();
			header("Location: index.php?e=3");
			exit;
		}
	}
} elseif($_SESSION['mfa_required']) {
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

		.container {
			background-color: #fff;
			padding: 30px;
			border-radius: 8px;
			box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
			text-align: center;
		}

		h1 {
			text-align: center;
			margin-bottom: 20px;
		}

		.form-group {
			margin-bottom: 15px;
		}

		label {
			display: block;
			margin-bottom: 5px;
		}

		input[type="text"],
		input[type="password"] {
			width: 100%;
			padding: 10px;
			border: 1px solid #ced4da;
			border-radius: 4px;
			box-sizing: border-box; 
		}

		button[type="submit"] {
			background-color: #28a745; 
			color: white;
			padding: 10px 20px;
			border: none;
			border-radius: 4px;
			cursor: pointer;
			width: 100%; 
		}
		
	</style>
</head>
<body>
	<div class="container">
		<img src="assets/logo.png" alt="KontrolVM Logo" style="display:block;margin:0 auto;" />
		<br />
		<br />
		<h1>Two-Factor Authentication</h1>
		<p>Please enter your OTP:
		<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
			<input type="hidden" name="staff_id" value="<?php echo htmlspecialchars($_SESSION['staff_id']);?>"> 
			<input type="text" name="otp" required>
			<br />
			<br />
			<button type="submit">Verify</button>
		</form>
		</p>
	</div>
</body>
</html>
<?php
} else {
	header("refresh:3;url=index.php");
	exit;
}
?>