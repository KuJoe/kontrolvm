<?PHP
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php"); 
	exit; 
} else {
	define('AmAllowed', TRUE);
	require_once('config.php');
	require_once('functions.php');
}
function updateFiles() {
	$apiUrl = "https://api.github.com/repos/KuJoe/kontrolvm/releases/latest";
    $options = [
        'http' => [
            'method' => 'GET',
            'header' => 'User-Agent: PHP Script'
        ]
    ];
	$context = stream_context_create($options);
    $response = @file_get_contents($apiUrl, false, $context);
    if (!$response) {
        return "Failed to fetch release information from GitHub.";
    }
    $releaseData = json_decode($response, true);
    if(!isset($releaseData['zipball_url'])) {
        return "Failed to parse release information.";
    }
	$releaseVersion = preg_replace('/[a-zA-Z-]/', '', $releaseData['tag_name']);
	if(checkVersion($releaseVersion) === true) {
		return "The latest release version is the same as the current version.";
	} else {
		$zipUrl = $releaseData['zipball_url'];
		$zipFilePath = tempnam(sys_get_temp_dir(), 'github_update_');
		$zipData = @file_get_contents($zipUrl);
		if(!$zipData) {
			return "Failed to download the zip archive.";
		}
		file_put_contents($zipFilePath, $zipData);
		$zip = new ZipArchive;
		if($zip->open($zipFilePath) !== true) {
			return "Failed to open the zip archive.";
		}
		$rootDirectory = $zip->getNameIndex(0);
		if(substr($rootDirectory, -1) !== '/') {
		  $rootDirectory = dirname($rootDirectory) . '/';
		}
		for ($i = 0; $i < $zip->numFiles; $i++) {
			$entryName = $zip->getNameIndex($i);
			$localName = str_replace($rootDirectory, '', $entryName);
			if(empty($localName)) {
				continue;
			}
			$targetPath = __DIR__ . '/' . $localName; // Use __DIR__ for the current directory
			if(substr($entryName, -1) === '/') {
				if(!file_exists($targetPath)) {
					mkdir($targetPath, 0755, true);
				}
			} else {
				$fileContent = $zip->getFromIndex($i);
				if($fileContent !== false) {
					file_put_contents($targetPath, $fileContent);
				}
			}
		}
		$zip->close();
		unlink($zipFilePath);
		return true;
	}
}
$resultFiles = updateFiles();
if($resultFiles === true) {
	header("Location: update_db.php");
	exit;
} else {
	$error = $resultFiles;
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
		<br /><br />
		<p style="text-align:center;font-size:0.9em;">Powered by <a href="https://github.com/KuJoe/kontrolvm" target="_blank">KontrolVM</a></p>
	</div>
</body>
</html>