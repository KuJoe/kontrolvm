<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if(isset($_SESSION["loggedin"]) AND $_SESSION["loggedin"] == true) {
	define('AmAllowed', TRUE);
	header("Location: home.php"); 
}
require_once('config.php');
if(isset($_GET['e'])) {
	if($_GET['e'] == '0') {
		$error = 'Incorrect username or password.';
	} elseif($_GET['e'] == '1') {
		$error = "CAPTCHA failed.";
	} elseif($_GET['e'] == '2') {
		$error = "User is locked out or not active.";
	} elseif($_GET['e'] == '3') {
		$error = "MFA verification failed.";
	} elseif($_GET['e'] == '4') {
		$success = "Your password has been reset and a new one has been e-mailed to you.";
	} else {
		$error = "Login failed.";
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

		.login-container {
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
		
		.success-message {
			color: #155724;
			background-color: #d4edda;
			border: 1px solid #c3e6cb;
			padding: 10px;
			margin-bottom: 15px;
			border-radius: 4px;
			text-align: center;
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
	<div class="login-container">
		<img src="assets/logo.png" alt="KontrolVM Logo" style="display:block;margin:0 auto;" />
		<br />
		<br />
		<?php if(isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if(isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<form action="auth.php" method="post"> 
			<div class="form-group">
				<label for="username">Username:</label>
				<input type="text" id="username" name="username" placeholder="username" maxlength="50" required>
			</div>
			<div class="form-group">
				<label for="password">Password:</label>
				<input type="password" id="password" name="password" placeholder="password" maxlength="50" required>
			</div>
			<?php if(isset($sitekey)) { ?>
				<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>
				<div class="cf-turnstile" data-sitekey="<?php echo $sitekey; ?>"></div>
			<?php } ?>
			<button type="submit">Login</button>
		</form>
		<p style="text-align:center;"><a href="password_reset.php">Reset Password</a></p>
		<br/ >
		<p style="text-align:center;font-size:0.9em;">Powered by <a href="https://github.com/KuJoe/kontrolvm" target="_blank">KontrolVM</a></p>
	</div>
</body>
</html>