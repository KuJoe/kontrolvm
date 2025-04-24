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

function fetchReleaseData($repoOwner, $repoName) {
	$apiUrl = "https://api.github.com/repos/{$repoOwner}/{$repoName}/releases/latest";
	$options = [
		'http' => [
			'method' => 'GET',
			'header' => 'User-Agent: PHP Script'
		]
	];
	$context = stream_context_create($options);
	$response = @file_get_contents($apiUrl, false, $context);

	if (!$response) {
		return false;
	}

	$releaseData = json_decode($response, true);
	if (!isset($releaseData['zipball_url']) || !isset($releaseData['tag_name'])) {
		return false;
	}
	return $releaseData;
}

function downloadAndExtractZip($zipUrl, $installPath) {
	$zipFilePath = tempnam(sys_get_temp_dir(), 'github_update_');
	$zipData = @file_get_contents($zipUrl);

	if (!$zipData) {
		return false;
	}

	file_put_contents($zipFilePath, $zipData);
	$zip = new ZipArchive;

	if ($zip->open($zipFilePath) !== true) {
		unlink($zipFilePath);
		return false;
	}

	$rootDirectory = $zip->getNameIndex(0);
	if (substr($rootDirectory, -1) !== '/') {
		$rootDirectory = dirname($rootDirectory) . '/';
	}

	for ($i = 0; $i < $zip->numFiles; $i++) {
		$entryName = $zip->getNameIndex($i);
		$localName = str_replace($rootDirectory, '', $entryName);

		if (empty($localName)) {
			continue;
		}

		$targetPath = $installPath . '/' . $localName;
		if (substr($entryName, -1) === '/') {
			if (!file_exists($targetPath)) {
				mkdir($targetPath, 0755, true);
			}
		} else {
			$fileContent = $zip->getFromIndex($i);
			if ($fileContent !== false) {
				file_put_contents($targetPath, $fileContent);
			}
		}
	}

	$zip->close();
	unlink($zipFilePath);
	return true;
}

function updateFiles($repoOwner = "KuJoe", $repoName = "kontrolvm") {
	$releaseData = fetchReleaseData($repoOwner, $repoName);

	if (!$releaseData) {
		return "Failed to fetch release information from GitHub.";
	}

	if(checkVersion() === true) {
		return "The latest release version is the same as the current version.";
	}

	$zipURL = $releaseData['assets']['0']['browser_download_url'];
	if (!downloadAndExtractZip($zipURL, __DIR__)) {
		return "Failed to download or extract the zip archive.";
	}

	return true;
}
$resultFiles = updateFiles();
if($resultFiles === true) {
	$servers = getServerList('1');
	if(count($servers) > 0) {
		foreach ($servers as $server) {
			updateKontrolVMNode($server['node_id']);
		}
	}
	if(!$error) {
		header("Location: update_db.php");
		exit;
	}
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
		<a href="home.php"><img src="assets/logo.png" alt="KontrolVM Logo" style="display:block;margin:0 auto;" /></a>
		<br />
		<br />
		<?php if(isset($error)) { ?>
			<h2 style="color:red;">Update Failed</h2>
			<br />
			<div class="error-message"><?php echo $error; ?><br /><br /><a href="logs.php"><strong>Check the logs for errors.</strong></a></div>
		<?php } ?>
		<br /><br />
		<p style="text-align:center;font-size:0.9em;">Powered by <a href="https://github.com/KuJoe/kontrolvm" target="_blank">KontrolVM</a></p>
	</div>
</body>
</html>