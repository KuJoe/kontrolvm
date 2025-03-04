<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
define('AmAllowed', TRUE);
require_once('config.php');
require_once('functions.php');
if($_SERVER["REQUEST_METHOD"] == "POST") {
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
			$error = "Error with CAPTCHA: " . $error_message;
			curl_close($curl);
		} else {
			$response = json_decode($response,true);
			if($response['error-codes'] && count($response['error-codes']) > 0){
				error_log("Cloudflare Turnstile check failed.");
				$error = "Error with CAPTCHA.";
				curl_close($curl);
			}
		}
		curl_close($curl);
	}
	if(isset($_POST['email'])) {
		if(sendPasswordResetEmail($_POST['email'])) {
			$success = "Password reset e-mail sent successfully.";
		} else {
			$error = "Password reset e-mail failed to send.";
		}
	}
}
if(isset($_GET['id']) AND isset($_GET['token'])) {
	if(verifyToken($_GET['token'],$_GET['id'])) {
		header("Location: index.php?e=4");
	} else {
		$error = "Password reset e-mail failed to send.";
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

		input[type="email"] {
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
		<h1>Password Reset</h1>
		<?php if(isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } elseif(isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } else { ?>
		<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
			<label for="email">E-mail Address:</label>
			<input type="email" id="email" name="email" required>
			<?php if(isset($sitekey)) { ?>
				<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>
				<div class="cf-turnstile" data-sitekey="<?php echo $sitekey; ?>"></div>
			<?php } ?>
			<br />
			<br />
			<button type="submit">Reset Password</button>
		</form>
		<?php } ?>
		<br /><br />
		<p style="text-align:center;font-size:0.9em;">Powered by <a href="https://github.com/KuJoe/kontrolvm" target="_blank">KontrolVM</a></p>
	</div>
</body>
</html>