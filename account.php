<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

require __DIR__ . '/vendor/autoload.php';
use PragmaRX\Google2FA\Google2FA;
use BaconQrCode\Renderer\GDLibRenderer;
use BaconQrCode\Writer;

session_start();
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
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
	if(isset($_GET['id'])) {
		$staff_id = $_GET['id'];
	} elseif(isset($_POST['id'])) {
		$staff_id = $_POST['id'];
	} elseif(isset($_SESSION['staff_id'])) {
		$staff_id = $_SESSION['staff_id'];
	} else {
		error_log("Error: Account ID missing.");
		exit;
	}
	$staff = getStaffDetails($staff_id);
	if(isset($_GET['s'])) {
		if ($_GET['s'] == '1') {
			$success = "Account updated successfully.";
		} elseif ($_GET['s'] == '2') {
			$success = "MFA enabled successfully.";
		} elseif ($_GET['s'] == '3') {
			$success = "MFA disabled successfully.";
		} 
	}
}
$csrfToken = getCSRFToken();
$google2fa = new Google2FA();
$mfasecret = $google2fa->generateSecretKey();
$g2faUrl = $google2fa->getQRCodeUrl(
	'KontrolVM',
	$_SESSION["username"],
	$mfasecret
);
$writer = new Writer(new GDLibRenderer(250));
$qrcode_image = base64_encode($writer->writeString($g2faUrl));

if($_SERVER["REQUEST_METHOD"] == "POST") {
	$token = $_POST["csrf_token"];
	if(validateCSRFToken($token)) {
		if(isset($_POST['save_account'])) {
			$username = $_POST['username'];
			$email = $_POST['email'];
			if($staff_id == '1') {
				$status = '1';
			} else {
				if(isset($_POST["status"])) {
					$status = '1';
				} else {
					$status = '0';
				}
			}
			if(isset($_POST["confirm-password"])) {
				$password1 = $_POST['new-password'];
				$password2 = $_POST['confirm-password'];
			} else {
				$password1 = NULL;
				$password2 = NULL;
			}
			$result = updateStaff($staff_id,$username,$email,$status,$password1,$password2);
			if($result === true) {
				if($_SESSION["staff_id"] == $_POST["id"]) {
					$_SESSION["username"] = $username;
				}
				header("Location: account.php?id=". (int)$staff_id. "&s=1");
			} else {
				$error = "Account update failed: ".$result;
			}
		}
		if(isset($_POST["mfa-verify"]) AND isset($_POST["enable_mfa"])) {
			$mfacode = $_POST["mfa-verify"];
			$mfasecret = $_POST["mfa_secret"];
			$result = enableMFA($staff_id,$mfasecret,$mfacode);
			if($result === true) {
				header("Location: account.php?id=". (int)$staff_id. "&s=2");
			} else {
				$error = "Account update failed: MFA failed to enable.";
			}
		}
		if(!isset($_POST["mfastate"]) AND isset($_POST["disable_mfa"])) {
			$result = disableMFA($staff_id);
			if($result === true) {
				header("Location: account.php?id=". (int)$staff_id. "&s=3");
			} else {
				$error = "Account update failed: MFA failed to disable.";
			}
		}
		if(isset($_POST['delete_account'])) {
			if($_SESSION["staff_id"] == $_POST["id"]) {
				$error = "User delete failed: You can't deleted yourself.";
			} else {
				if (isset($_POST['confirm'])) {
					$confirm = $_POST['confirm'];
					$result = deleteUser($_POST["id"],$confirm);
					if($result === true) {
						header("Location: users.php?s=2");
					} else {
						$error = "User delete failed: ".$result;
					}
				} else {
					$error = "User delete failed: Please make sure you checked the confirmation box.";
				}
			}
		}
	} else {
		$error = "Invalid CSRF token.";
	}
}

if ($staff) {
	if($staff_id == '1') {
		$state = " checked disabled";
	} else {
		if($staff['staff_active'] == "1") {
			$state = " checked";
		} else {
			$state = "";
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
			<li><a href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a class="active" href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<div class="container">
		<h1>Manage Account</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<form id="save_account" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
		<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
		<input type="hidden" name="id" value="<?php echo htmlspecialchars($staff_id); ?>">
			<h2>Profile</h2>
			<div class="form-group">
				<label for="username">Username:</label>
				<input type="text" id="username" name="username" value="<?php echo $staff["staff_username"]; ?>" minlength="4" maxlength="30"> 
			</div>
			<div class="form-group">
				<label for="email">E-mail Address:</label>
				<input type="email" id="email" name="email" value="<?php echo $staff["staff_email"]; ?>">
			</div>
			<div class="form-group" style="width:200px;">
				<label for="status">Active: </label>
				<input type="checkbox" id="status" name="status"<?php echo $state; ?>>
			</div>
			<h2>Change Password <input type="checkbox" id="password-change" name="password-change"></h2>
			<div class="form-group password-options">
				<label for="new-password">New Password:</label>
				<input type="password" id="new-password" name="new-password">
			</div>
			<div class="form-group password-options">
				<label for="confirm-password">Confirm New Password:</label>
				<input type="password" id="confirm-password" name="confirm-password">
			</div>
			<br />			
			<button type="submit" class="stylish-button" name="save_account">Save Changes</button>
		</form>
		<br />
		<hr />
		<?php if(empty($staff["staff_mfa"])) { ?>
		<form id="enable_mfa" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
		<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
		<input type="hidden" name="id" value="<?php echo htmlspecialchars($staff_id); ?>">
		<input type="hidden" name="mfa_secret" value="<?php echo htmlspecialchars($mfasecret); ?>">
			<br />
			<h2>Enable MFA <input type="checkbox" id="mfa-change" name="mfa-change"> </h2>
			<div class="form-group mfa-options">
				<p>
				<img src="data:image/png;base64, <?php echo $qrcode_image; ?> "/><br />
				<span style="padding-left:22px;"><small>Secret Key: <?php echo $mfasecret; ?></small>
				</p>
				<br />
				<label for="mfa-verify">Verify MFA:</label>
				<input type="text" id="mfa-verify" name="mfa-verify">
				<br /><br />
				<button type="submit" class="stylish-button" name="enable_mfa">Save Changes</button>
			</div>
		</form>
		<?php } else { ?>
		<form id="disable_mfa" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
		<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
		<input type="hidden" name="id" value="<?php echo htmlspecialchars($staff_id); ?>">
			<br />
			<h2>Disable MFA <input type="checkbox" id="mfastate" name="mfastate" checked></h2>
			<br /><br />
			<button type="submit" class="stylish-button" name="disable_mfa">Save Changes</button>
		</form>
		<?php } ?>
		<?php if ($staff_id > "1") { ?>
		<br />
		<hr />
		<br />
		<table>
			<tr>
				<td style="background-color:#999;">DELETE ACCOUNT:</td>
				<td style="padding:10px;">
				<form id="delete_account" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
				<label class="checkbox-container" style="padding:5px;">
					<input type="checkbox" name="confirm" style="padding:5px;">
					<span class="checkmark"></span>
				</label>
				Confirm
				</td>
				<td>
				<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
				<input type="hidden" name="id" value="<?php echo htmlspecialchars($staff_id); ?>">
				<button type="submit" name="delete_account" id="delete_account" class="stylish-button" style="background-color:red;">DELETE</button>
				</form>
				</td>
			</tr>					
		</table>
		<?php } ?>
	</div>
<?php
} else {
	error_log("Error finding account.");
	exit;
}
?>
<?php include('footer.php'); ?>
	<script>
		// JavaScript code to handle theme switching
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
		// Ensure this code runs after the DOM is fully loaded
		document.addEventListener('DOMContentLoaded', function() {
			// Show/hide password options based on checkbox state
			const pwChange = document.getElementById('password-change');
			const pwOptions = document.querySelectorAll('.password-options');

			pwChange.addEventListener('change', function() {
			if (this.checked) {
				pwOptions.forEach(option => option.style.display = 'block');
			} else {
				pwOptions.forEach(option => option.style.display = 'none');
			}
			});

			// Trigger the change event initially to set the correct state on page load
			pwChange.dispatchEvent(new Event('change'));
		});
		document.addEventListener('DOMContentLoaded', function() {
			// Show/hide MFA options based on checkbox state
			const mfaChange = document.getElementById('mfa-change');
			const mfaOptions = document.querySelectorAll('.mfa-options');

			mfaChange.addEventListener('change', function() {
			if (this.checked) {
				mfaOptions.forEach(option => option.style.display = 'block');
			} else {
				mfaOptions.forEach(option => option.style.display = 'none');
			}
			});

			// Trigger the change event initially to set the correct state on page load
			mfaChange.dispatchEvent(new Event('change'));
		});
	</script>
</body>
</html>