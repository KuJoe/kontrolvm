<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start(); // Start the session

// Unset all session variables
$_SESSION = array();

// If it's desired to kill the session, also delete the session cookie.
// Note: This will destroy the session, and not just the session data!
if (ini_get("session.use_cookies")) {
		$params = session_get_cookie_params();
		setcookie(session_name(), '', time() - 42000,
				$params["path"], $params["domain"],
				$params["secure"], $params["httponly"]
		);
}

// Finally, destroy the session
session_destroy();

// Clear all cookies
foreach ($_COOKIE as $key => $value) {
	setcookie($key, '', time() - 3600, '/'); // Set expiration to the past
}

// Redirect to index.php after 3 seconds
header("refresh:3;url=index.php");

?>

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Logging Out</title>
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
		<h1>Logging Out</h1>
		<p>You have been logged out. Redirecting to the home page in 3 seconds...</p>
		<div class="loader"></div> 
	</div>
</body>
</html>