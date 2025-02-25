<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

if(!defined('AmAllowed')) {
	die('Error 001A');
}
define('KONTROLVM_VERSION', '0.1');
require_once('config.php');
require __DIR__ . '/vendor/autoload.php';
use phpseclib3\Net\SSH2;
use phpseclib3\Crypt\PublicKeyLoader;
use PragmaRX\Google2FA\Google2FA;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

function getRealUserIp() {
	switch(true){
		case (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) : return $_SERVER['HTTP_CF_CONNECTING_IP'];
		case (!empty($_SERVER['HTTP_X_REAL_IP'])) : return $_SERVER['HTTP_X_REAL_IP'];
		case (!empty($_SERVER['HTTP_CLIENT_IP'])) : return $_SERVER['HTTP_CLIENT_IP'];
		case (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) : return $_SERVER['HTTP_X_FORWARDED_FOR'];
		default : return $_SERVER['REMOTE_ADDR'];
	}
}

function logError($message) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare('INSERT INTO logs (log_message) VALUES (:log_message)');
		$stmt->bindValue(':log_message', "$message", SQLITE3_TEXT);
		$result = $stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error writing log ($message): " . $e->getMessage());
		return false; 
	}
}

function generateRandomString($length = 16) {
	$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$charactersLength = strlen($characters);
	$randomString = '';
	for ($i = 0; $i < $length; $i++) {
		$randomString .= $characters[rand(0, $charactersLength - 1)];
	}
	return $randomString;
}

function getCSRFToken() {
	$token = mt_rand();
	if(empty($_SESSION['csrf_tokens'])) {
			$_SESSION['csrf_tokens'] = array();
	}
	$_SESSION['csrf_tokens'][$token] = true;
	return $token;
}

function validateCSRFToken($token) {
	if(isset($_SESSION['csrf_tokens'][$token])) {
		unset($_SESSION['csrf_tokens'][$token]);
		return true;
	}
	return false;
}

function secondsToHumanReadable($seconds) {
	$dtF = new \DateTime('@0');
	$dtT = new \DateTime("@$seconds");
	return $dtF->diff($dtT)->format('%a days, %h hours, %i minutes, %s seconds');
}

function calcDisk($disk) {
	$total_disk = trim($disk);
	preg_match('/([\d\.]+)([TGMK])/', $total_disk, $matches);
	$value = $matches[1];
	$unit = $matches[2];

	// Convert to gigabytes
	switch ($unit) {
		case 'T':
		$disk = $value * 1024;
		break;
		case 'G':
		$disk = $value;
		break;
		case 'M':
		$disk = $value / 1024;
		break;
		case 'K':
		$disk = $value / 1024 / 1024;
		break;
	}
	
	$output = ceil($disk * 100) / 100;
	return $output;
}

function connectNode($node_id) {
	$node = getNodeDetails((int)$node_id);
	$connection = @fsockopen($node['ipaddr'], $node['sshport'], $errno, $errstr, 2);
	if (is_resource($connection)) {
		fclose($connection);
		$ssh = new SSH2($node['ipaddr'], $node['sshport'], 5);
		$key = PublicKeyLoader::load(file_get_contents($node['sshkey']));
		//$ssh->enablePTY();
		$ssh->setTimeout(30);
		$ssh->login($node['sshuser'], $key);
		if ($ssh->isConnected()) {
			return $ssh;
		} else {
			$error = $ssh->getLastError();
			logError("SSH connection failed for $node_id: $error");
			return false;
		}
	} else {
		return false;
	}
}

function encrypt($string) {
	include('config.php');
	$cipher = "AES-256-CBC";
	$iv = random_bytes(openssl_cipher_iv_length($cipher));
	$encrypted_string = openssl_encrypt($string, $cipher, $cryptkey, 0, $iv);
	return base64_encode($encrypted_string. '::'. $iv);
}

function decrypt($encrypted_string) {
	include('config.php');
	$cipher = "AES-256-CBC";
	$data = base64_decode($encrypted_string);
	$iv = random_bytes(openssl_cipher_iv_length($cipher));
	list($encrypted_data, $iv) = explode('::', $data);
	return openssl_decrypt($encrypted_data, $cipher, $cryptkey, 0, $iv);
}

function sendMail($message,$subject,$email) {
	include('config.php');
	if(isset($smtp_server)) {
		$mail = new PHPMailer(true);
		try {
			$mail->SMTPDebug = SMTP::DEBUG_OFF;
			$mail->isSMTP();
			$mail->Host			 = $smtp_server;
			$mail->SMTPAuth	 = true;
			$mail->Username	 = $smtp_user;
			$mail->Password	 = $smtp_password;
			if($smtp_tls) {
				$mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
			}
			$mail->Port			 = $smtp_port;

			// Recipients
			$mail->setFrom($smtp_sender, 'KontrolVM');
			$mail->addAddress($email, 'KontrolVM User');

			// Content
			$mail->isHTML(true);
			$mail->Subject = $subject;
			$mail->Body		= $message;
			$mail->AltBody = strip_tags($message);

			$mail->send();
			return true;
		} catch (Exception $e) {
			logError("Mailer Error: ".$mail->ErrorInfo);
			return false;
		}
	} else {
		logError("Mailer sending error: Please configure the SMTP settings in config.php");
		return false;
	}
}

function checkActive($staff_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("SELECT staff_active FROM staff WHERE staff_id =:staff_id");
		$stmt->bindParam(':staff_id', $staff_id, SQLITE3_INTEGER);
		$stmt->execute();
		$active = $stmt->fetchColumn();
		if($active > "0") {
			return true;
		} else {
			return false;
		}
	} catch(PDOException $e) {
		die("Database error: " . $e->getMessage());
	}
	return false;
}

function checkLockedOut($staff_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$sql = "SELECT staff_locked FROM staff WHERE staff_id =:staff_id";
		$stmt = $conn->prepare($sql);
		$stmt->bindParam(':staff_id', $staff_id, SQLITE3_INTEGER);
		$stmt->execute();
		$locked = $stmt->fetchColumn();
		if ($locked) {
			$locked_datetime = DateTime::createFromFormat('Y-m-d H:i:s', $locked);
			$now = new DateTime();
			if ($locked_datetime > $now) {
				return true;
			} else {
				return false;
			}
		} else {
			return false;
		}
	} catch(PDOException $e) {
		logError("Database error (checkLockedOut): " . $e->getMessage());
		return false;
	}
	return false;
}


function createUser($username,$email) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$password = generateRandomString();
		$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
		$stmt = $conn->prepare('INSERT INTO staff (staff_username, staff_email, staff_password) VALUES (:username, :email, :password)');
		$stmt->bindValue(':username', "$username", SQLITE3_TEXT);
		$stmt->bindValue(':email', "$email", SQLITE3_TEXT);
		$stmt->bindValue(':password', "$hashedPassword", SQLITE3_TEXT);
		$result = $stmt->execute();
		return $password;
	} catch (PDOException $e) {
		logError("Error creating staff: " . $e->getMessage());
		return false; 
	}
}

function deleteUser($staff_id,$confirm) {
	if($confirm = 1) {
		include('config.php');
		$conn = new PDO("sqlite:$db_file_path");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		try {
			if($staff_id > "1") {
				$stmt = $conn->prepare('DELETE FROM staff WHERE staff_id =:staff_id');
				$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
				$result = $stmt->execute();
				return true;
			} else {
				logError("Cannot delete ID 1 account.");
				return false;
			}
		} catch (PDOException $e) {
			logError("Error deleting staff: " . $e->getMessage());
			return false; 
		}
	} else {
		logError("No confirmation ($staff_id): " . $e->getMessage());
		return false;
	}
}

function updateStaff($staff_id,$username,$email,$status,$password1,$password2) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		if(!is_null($password2)) {
			if($password1 = $password2) {
				$password = password_hash($password1, PASSWORD_DEFAULT);
				$stmt = $conn->prepare("UPDATE staff SET staff_username =:username, staff_email =:email, staff_active =:status, staff_password =:password WHERE staff_id =:staff_id");
				$stmt->bindValue(':username', "$username", SQLITE3_TEXT);
				$stmt->bindValue(':email', "$email", SQLITE3_TEXT);
				$stmt->bindValue(':status', $status, SQLITE3_INTEGER);
				$stmt->bindValue(':password', "$password", SQLITE3_TEXT);
				$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
				$stmt->execute();
				return true;
			} else {
				logError("Error updating account ($staff_id): password mismatch");
				return false;
			}
		} else {
			$stmt = $conn->prepare("UPDATE staff SET staff_username =:username, staff_email =:email, staff_active =:status WHERE staff_id =:staff_id");
			$stmt->bindValue(':username', "$username", SQLITE3_TEXT);
			$stmt->bindValue(':email', "$email", SQLITE3_TEXT);
			$stmt->bindValue(':status', $status, SQLITE3_INTEGER);
			$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
			$stmt->execute();
			return true;
		}
	} catch (PDOException $e) {
		logError("Error updating account ($staff_id): " . $e->getMessage());
		return false; 
	}
}

function getStaffDetails($staff_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$sql = "SELECT * FROM staff WHERE staff_id =:staff_id";
		$stmt = $conn->prepare($sql);
		$stmt->bindParam(':staff_id', $staff_id, SQLITE3_INTEGER);
		$stmt->execute();
		$staff = $stmt->fetch(PDO::FETCH_ASSOC);
		return $staff; 
	} catch (PDOException $e) {
		logError("Error fetching staff details: " . $e->getMessage());
		return false; 
	}
}

function getClusterName($loc) {
	$loc = trim($loc);
	include('config.php');
	try {
		$conn = new PDO("sqlite:$db_file_path");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		$sql = "SELECT friendlyname FROM clusters WHERE loc =:loc";
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':loc', "$loc", SQLITE3_TEXT);
		$stmt->execute();

		$friendlyname = $stmt->fetchColumn();
		return $friendlyname;

	} catch (PDOException $e) {
		logError("Error fetching node name: ". $e->getMessage());
		return false; // Or handle the error differently
	}
}

function getNodeName($node_id) {
	include('config.php');
	try {
		$conn = new PDO("sqlite:$db_file_path");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		$sql = "SELECT hostname FROM nodes WHERE node_id =:node_id";
		$stmt = $conn->prepare($sql);
		$stmt->bindParam(':node_id', $node_id, SQLITE3_INTEGER);
		$stmt->execute();

		$hostname = $stmt->fetchColumn();
		return $hostname;

	} catch (PDOException $e) {
		logError("Error fetching node name: ". $e->getMessage());
		return false; // Or handle the error differently
	}
}

function addNode($hostname, $ipaddr, $sshport, $rootpw, $loc) {
	include('config.php');
	try {
		$rootpw = trim($rootpw);
		$ssh = new SSH2($ipaddr, $sshport);
		$ssh->login('root', $rootpw);
		if ($ssh->isConnected()) {
			$ssh->setTimeout(60);
			$kversion = $ssh->exec("/usr/bin/cat /home/kontrolvm/conf/kontrolvm.conf");
			if(trim($kversion) !== "kontrolvm_version=".KONTROLVM_VERSION) {
				throw new Exception("KontrolVM not installed or incorrect version.");
			}
			$sshkeypublic = file_get_contents($sshkeypub);
			$kontrolvmip = $_SERVER['SERVER_ADDR'];
			$sshkeypublic = 'from="'.$kontrolvmip.'" '.$sshkeypublic;
			$ssh->exec("echo '$sshkeypublic' >> /home/kontrolvm/.ssh/authorized_keys");
			$kontrolvm_url = dirname((empty($_SERVER['HTTPS']) ? 'http' : 'https') . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]");
			$ssh->exec("echo 'kontrolvm_url=$kontrolvm_url' >> /home/kontrolvm/conf/kontrolvm.conf");
			$ssh->disconnect();
		} else {
			throw new Exception("SSH connection with password failed.");
		}
	} catch (Exception $e) {
		$error = ($e->getMessage());
		return $error;
	}
	try {
		$conn = new PDO("sqlite:$db_file_path");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$stmt = $conn->prepare('INSERT INTO nodes (hostname, ipaddr, sshport, loc, sshuser, sshkey, lastvnc, lastws, lastvm, status, last_updated) VALUES (:hostname, :ipaddr, :sshport, :loc, :sshuser, :sshkey, :lastvnc, :lastws, :lastvm, :status, :last_updated)');
		$stmt->bindValue(':hostname', "$hostname", SQLITE3_TEXT);
		$stmt->bindValue(':ipaddr', "$ipaddr", SQLITE3_TEXT);
		$stmt->bindValue(':sshport', $sshport, SQLITE3_INTEGER);
		$stmt->bindValue(':sshuser', "$sshusernow", SQLITE3_TEXT);
		$stmt->bindValue(':sshkey', "$sshkeypriv", SQLITE3_TEXT);
		$stmt->bindValue(':loc', "$loc", SQLITE3_TEXT);
		$stmt->bindValue(':lastvnc', '5901', SQLITE3_INTEGER);
		$stmt->bindValue(':lastws', '6901', SQLITE3_INTEGER);
		$stmt->bindValue(':lastvm', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':last_updated', time(), SQLITE3_TEXT);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = $e->getMessage();
		return $error;
	}
	
}

function deleteNode($node_id,$hostname,$confirm) {
	if($confirm = 1) {
		$hostname = trim($hostname);
		include('config.php');
		$conn = new PDO("sqlite:$db_file_path");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		try {
			$sql = "DELETE FROM nodes WHERE node_id =:node_id AND hostname =:hostname";
			$stmt = $conn->prepare($sql);
			$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
			$stmt->bindValue(':hostname', "$hostname", SQLITE3_TEXT);
			$stmt->execute();
			return true;
		} catch (PDOException $e) {
			logError("Error deleting node: ". $e->getMessage());
			return false;
		}
	} else {
		logError("No confirmation ($node_id): " . $e->getMessage());
		return false;
	}
}

function updateNode($node_id, $node_data) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$node_data[':node_id'] = $node_id;
	$node_data[':last_updated'] = time();
	$stmt = $conn->prepare("UPDATE nodes SET cpu_cores =:cpu_cores,total_memory =:total_memory,disk_space =:disk_space,make =:make,model =:model,cpu =:cpu,vms =:vms,os_version =:os_version,kernel_version =:kernel_version,libvirt_version =:libvirt_version,last_updated =:last_updated WHERE node_id =:node_id");
	if ($stmt->execute($node_data)) {
		return true;
	} else {
		$error = "Error updating node: " . $conn->lastErrorMsg();
		return $error;
	}
}

function editNode($node_id, $node_data) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$node_data[':node_id'] = $node_id;
	$node_data[':last_updated'] = time();
	$stmt = $conn->prepare("UPDATE nodes SET hostname =:hostname,ipaddr =:ipaddr,sshport =:sshport,status =:status,lastvm =:lastvm,lastvnc =:lastvnc,lastws =:lastws,loc =:loc,last_updated =:last_updated WHERE node_id =:node_id");

	if ($stmt->execute($node_data)) {
		return true;
	} else {
		$error = "Error editing node: " . $conn->lastErrorMsg();
		return $error;
	}
}

function editVM($vm_id,$vm_data) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$encpw = encrypt($vncpw);
	$vm_data[':vm_id'] = $vm_id;
	$vm_data[':last_updated'] = time();
	$stmt = $conn->prepare("UPDATE vms SET name =:name,hostname =:hostname,notes =:notes,mac_address =:mac_address,vncpw =:vncpw,vncport =:vncport,websockify =:websockify,loc =:loc,status =:status,protected =:protected,last_updated =:last_updated WHERE vm_id =:vm_id");

	if ($stmt->execute($vm_data)) {
		return true;
	} else {
		$error = "Error editing VM: " . $conn->lastErrorMsg();
		return $error;
	}
}

function getNodeDetails($node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$sql = "SELECT * FROM nodes WHERE node_id =:node_id";
		$stmt = $conn->prepare($sql);
		$stmt->bindParam(':node_id', $node_id, SQLITE3_INTEGER);
		$stmt->execute();
		$node = $stmt->fetch(PDO::FETCH_ASSOC);
		return $node; 
	} catch (PDOException $e) {
		logError("Error fetching node details: " . $e->getMessage());
		return false; 
	}
}

function getVMDetails($vm_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$sql = "SELECT * FROM vms WHERE vm_id =:vm_id";
		$stmt = $conn->prepare($sql);
		$stmt->bindParam(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		$node = $stmt->fetch(PDO::FETCH_ASSOC);
		return $node; 
	} catch (PDOException $e) {
		logError("Error fetching node details: " . $e->getMessage());
		return false; 
	}
}

function getNodeStats($node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$uptime_string = $ssh->exec('uptime'); 
		preg_match('/up (.*?),/', $uptime_string, $matches);
		$uptime = $matches[1];
		$load = $ssh->exec("/usr/bin/cat /proc/loadavg | awk '{print $1}'");
		$disk = $ssh->exec("/usr/bin/df -h /home/ | awk 'NR==2{print $5}'");
		$memused = $ssh->exec("/usr/bin/free -m | awk 'NR==2{printf \"%.2f%%\", $3*100/$2 }'");
		#echo $ssh->getLog();
		$ssh->disconnect();
		
		
		$stmt = $conn->prepare("UPDATE nodes SET uptime =:uptime, load =:load, memused =:memused, diskclnt =:diskclnt, last_updated =:last_updated WHERE node_id =:node_id");
		$stmt->bindValue(':uptime', "$uptime", SQLITE3_TEXT);
		$stmt->bindValue(':load', "$load", SQLITE3_TEXT);
		$stmt->bindValue(':memused', "$memused", SQLITE3_TEXT);
		$stmt->bindValue(':diskclnt', "$disk", SQLITE3_TEXT);
		$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
		$stmt->bindValue(':last_updated', time(), SQLITE3_INTEGER);
		$stmt->execute();
	} catch (PDOException $e) {
		logError("Error fetching node details: " . $e->getMessage());
		return false; 
	}
}

function getNodeInfo($node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		// Get RAM amount
		$ram = $ssh->exec("free -h | grep Mem | awk '{print $2}'");
		$total_memory = trim($ram);
		preg_match('/([\d\.]+)([GMK])/', $total_memory, $matches);
		$value = $matches[1];
		$unit = $matches[2];

		if ($unit == "G") {
			$ram = $value;
		} elseif ($unit == "M") {
			$ram = $value / 1024;
		} elseif ($unit == "K") {
			$ram = $value / 1024 / 1024;
		}

		// Get CPU core count
		$cpu = $ssh->exec('cat /proc/cpuinfo | grep "processor" | wc -l');
		$cpumodel = $ssh->exec("cat /proc/cpuinfo | grep 'model name' | head -n 1");
		$cpumodel = trim(mb_substr($cpumodel, 13));

		// Get total disk space
		$total_disk = $ssh->exec("df -h /home/kontrolvm | awk 'NR==2{print $2}'");
		$total_disk = calcDisk($total_disk);
		$used_disk = $ssh->exec("df -h /home/kontrolvm | awk 'NR==2{print $3}'");
		$used_disk = calcDisk($used_disk);

		// Get make and model
		$make = $ssh->exec("sudo dmidecode | grep -A3 '^System Information' | grep 'Manufacturer'");
		$make = mb_substr($make, 14);
		$make = trim(str_replace([',', '.'], '', $make));
		$model = $ssh->exec("sudo dmidecode | grep -A3 '^System Information' | grep 'Product Name'");
		$model = mb_substr($model, 14);
		$model = trim(str_replace([',', '.'], '', $model)); 

		// Get number of VMs (XML files)
		$vms = $ssh->exec("sudo virsh list --all | grep kvm | wc -l");

		// Get OS Information
		$os_version = $ssh->exec('cat /etc/os-release | grep "PRETTY_NAME"');
		$os_version = trim(mb_substr($os_version, 12));
		$kernel_version = $ssh->exec('uname -r');
		$libvirt_version = $ssh->exec('virsh --version');
		
		$ssh->disconnect();
		$node_data = [':cpu_cores' => $cpu,':total_memory' => $ram,':disk_space' => $total_disk,':make' => $make,':model' => $model,':cpu' => $cpumodel,':vms' => $vms,':os_version' => $os_version,':kernel_version' => $kernel_version,':libvirt_version' => $libvirt_version];
		updateNode($node_id, $node_data);
		return true;
	} catch (Exception $e) {
		logError("Error connecting to $node_id: " . $e->getMessage());
		return;
	}
}

function getServerList($status) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		if($status == "all") {
			$sql = "SELECT * FROM nodes ORDER BY hostname";
		} else {
			$sql = "SELECT * FROM nodes WHERE status = $status ORDER BY hostname";
		}
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$servers = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $servers;
	} catch (PDOException $e) {
		logError("Error fetching server list: " . $e->getMessage());
		return false;
	}
}

function getClusters($status) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if($status == "all") {
		$sql = "SELECT * FROM clusters ORDER BY friendlyname";
		} else {
			$sql = "SELECT * FROM clusters WHERE status = $status ORDER BY friendlyname";
		}
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$clusters = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $clusters;
	} catch (PDOException $e) {
		logError("Error fetching cluster list: " . $e->getMessage());
		return false;
	}
}

function getUserList($status) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	if($status == "all") {
		$sql = "SELECT * FROM staff ORDER BY staff_id";
	} else {
		$sql = "SELECT * FROM staff WHERE staff_active = $status ORDER BY staff_id";
	}

	try {
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$users = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $users;
	} catch (PDOException $e) {
		logError("Error fetching user list: " . $e->getMessage());
		return false;
	}
}

function getVMState($vmname,$node_id) {
	include('config.php');
	try {
		$ssh = connectNode($node_id);
		$status = $ssh->exec("sudo virsh list --all | grep $vmname | awk '{print $3}'");
		#echo $ssh->getLog();
		$ssh->disconnect();
		return trim($status);
	} catch (PDOException $e) {
		logError("Error stopping VM ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function getVMList($status) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	if($status == "all") {
		$sql = "SELECT * FROM vms ORDER BY name";
	} else {
		$sql = "SELECT * FROM vms WHERE status = $status ORDER BY name";
	}

	try {
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$servers = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $servers;
	} catch (PDOException $e) {
		logError("Error fetching VM list: " . $e->getMessage());
		return false;
	}
}

function getISOs() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("SELECT * FROM ostemplates ORDER BY friendlyname");
		$stmt->execute();
		$isos = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $isos;
	} catch (PDOException $e) {
		logError("Error fetching ISOs list: " . $e->getMessage());
		return false;
	}
}

function addISOs($download, $friendlyname) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$path_parts = parse_url($download);
	$path_parts = explode("/", $path_parts['path']);
	foreach ($path_parts as $part) {
		if (preg_match('/\.iso$/', $part)) {
			$filename = $part;
		}
	}
	$rundl = downloadISOs($download, $filename);
	if($rundl === true) {
		$stmt = $conn->prepare('INSERT INTO ostemplates (filename, friendlyname, type, variant, status, added) VALUES (:filename, :friendlyname, :type, :variant, :status, :added)');
		$stmt->bindValue(':filename', "$filename", SQLITE3_TEXT);
		$stmt->bindValue(':friendlyname', "$friendlyname", SQLITE3_TEXT);
		$stmt->bindValue(':type', "$variant", SQLITE3_TEXT);
		$stmt->bindValue(':variant', "$variant", SQLITE3_TEXT);
		$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':added', time(), SQLITE3_TEXT); 
		$result = $stmt->execute();
		
		if ($result) {
			return true;
		} else {
			$error = "Error adding ISO: " . $conn->lastErrorMsg();
			return $error;
		}
	} else {
		$error = "Error downloading ISO";
		return $error;
	}
}

function downloadISOs($download, $filename) {
	$servers = getServerList('1');
	foreach ($servers as $server) {
		try {
			$node_id = $server['node_id'];
			$ssh = connectNode($node_id);
			$ssh->exec('wget -O /home/kontrolvm/isos/'.$filename.' '.$download.' &');
			sleep(1);
			#echo $ssh->getLog();
			$ssh->disconnect();
			return true;
		} catch (PDOException $e) {
			logError("Error downloading ISO ($node_id): " . $e->getMessage());
			return false; 
		}
	}
	return true;
}

function getIPs($version) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	if($version == "v6") {
		$sql = "SELECT * FROM ipv6";
	} else {
		$sql = "SELECT * FROM ipv4";
	}

	try {
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$ips = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $ips;
	} catch (PDOException $e) {
		logError("Error fetching IPs: " . $e->getMessage());
		return false;
	}
}

function addIPs($ipaddress, $gwip, $loc) {
	$ipaddress = trim($ipaddress);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	if(filter_var($ipaddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		$sql = "SELECT COUNT(*) FROM ipv4 WHERE ipaddress =':ipaddress'";
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':ipaddress', "$ipaddress", SQLITE3_TEXT);
		$stmt->execute();
		$count = $stmt->fetchColumn();
		if ($count > 0) {
			$error = "IP address exists.";
			return $error;
		} else {
			$stmt = $conn->prepare('INSERT INTO ipv4 (ipaddress, gwip, node, loc, vmid, status, reserved, notes, last_updated) VALUES (:ipaddress, :gwip, :node, :loc, :vmid, :status, :reserved, :notes, :last_updated)');
		}
	} else {
		$checkip = $ipaddress."::";
		if(filter_var($checkip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			$sql = 'SELECT COUNT(*) FROM ipv6 WHERE ipaddress =:ipaddress';
			$stmt = $conn->prepare($sql);
			$stmt->bindValue(':ipaddress', "$ipaddress", SQLITE3_TEXT);
			$stmt->execute();
			$count = $stmt->fetchColumn();
			if ($count > 0) {
				$error = "IP address exists.";
				return $error;
			} else {
				$stmt = $conn->prepare('INSERT INTO ipv6 (ipaddress, gwip, node, loc, vmid, status, reserved, notes, last_updated) VALUES (:ipaddress, :gwip, :node, :loc, :vmid, :status, :reserved, :notes, :last_updated)');
			}
		} else {
			$error = "Not a valid IP address.";
			return $error;
		}
	}
	$stmt->bindValue(':ipaddress', "$ipaddress", SQLITE3_TEXT);
	$stmt->bindValue(':gwip', "$gwip", SQLITE3_TEXT);
	$stmt->bindValue(':node', '0', SQLITE3_TEXT);
	$stmt->bindValue(':loc', "$loc", SQLITE3_TEXT);
	$stmt->bindValue(':vmid', '0', SQLITE3_INTEGER);
	$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
	$stmt->bindValue(':reserved', '0', SQLITE3_INTEGER);
	$stmt->bindValue(':notes', ' ', SQLITE3_TEXT);
	$stmt->bindValue(':last_updated', time(), SQLITE3_TEXT);

	$result = $stmt->execute();

	if ($result) {
		return true;
	} else {
		$error = "Error inserting data: " . $conn->lastErrorMsg();
		return $error;
	}
}

function deleteIP($ipid,$ipaddress) {
	$ipaddress = trim($ipaddress);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if(filter_var($ipaddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$sql = "DELETE FROM ipv4 WHERE ipid =:ipid";
		} else {
			$sql = "DELETE FROM ipv6 WHERE ipid =:ipid";
		}
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':ipid', $ipid, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error deleting row: ". $e->getMessage());
		return false;
	}
}

function reserveIP($ipid,$ipaddress) {
	$ipaddress = trim($ipaddress);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if(filter_var($ipaddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$sql = "UPDATE ipv4 SET reserved =:reserved WHERE ipid =:ipid";
		} else {
			$sql = "UPDATE ipv6 SET reserved =:reserved WHERE ipid =:ipid";
		}
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':reserved', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':ipid', $ipid, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error updating row: ". $e->getMessage());
		return false;
	}
}

function unreserveIP($ipid,$ipaddress) {
	$ipaddress = trim($ipaddress);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if(filter_var($ipaddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$sql = "UPDATE ipv4 SET reserved =:reserved WHERE ipid =:ipid";
		} else {
			$sql = "UPDATE ipv6 SET reserved =:reserved WHERE ipid =:ipid";
		}
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':reserved', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':ipid', $ipid, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error updating row: ". $e->getMessage());
		return false;
	}
}

function getTotalCPU() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$sql = "SELECT SUM(cpu_cores) AS total_cores FROM nodes";
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$result = $stmt->fetch(PDO::FETCH_ASSOC);
		$total_cores = $result['total_cores'];
		if($total_cores) {
			return $total_cores;
		} else {
			return "0";
		}
	} catch (PDOException $e) {
		logError("Error calculating total CPU cores: " . $e->getMessage());
		return "0";
	}
}

function getTotalDisk() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$sql = "SELECT SUM(disk_space) AS total_disk FROM nodes";
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$result = $stmt->fetch(PDO::FETCH_ASSOC);
		$total_disk = $result['total_disk'];
		if($total_disk) {
			return $total_disk;
		} else {
			return "0";
		}
	} catch (PDOException $e) {
		logError("Error calculating total disk space: " . $e->getMessage());
		return "0";
	}
}

function getTotalRAM() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$sql = "SELECT SUM(total_memory) AS total_ram FROM nodes";
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$result = $stmt->fetch(PDO::FETCH_ASSOC);
		$total_ram = $result['total_ram'];
		if($total_ram) {
			return $total_ram;
		} else {
			return "0";
		}
	} catch (PDOException $e) {
		logError("Error calculating total RAM: " . $e->getMessage());
		return "0";
	}
}

function getTotalVMs() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$sql = "SELECT SUM(vms) AS total_vms FROM nodes";
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$result = $stmt->fetch(PDO::FETCH_ASSOC);
		$total_vms = $result['total_vms'];
		if($total_vms) {
			return $total_vms;
		} else {
			return "0";
		}
	} catch (PDOException $e) {
		logError("Error calculating total VMs: " . $e->getMessage());
		return "0";
	}
}

function getTotalNodes() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$sql = "SELECT COUNT(*) FROM nodes WHERE status = 1";
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$count = $stmt->fetchColumn(); // Fetch the count directly
		if($count) {
			return $count;
		} else {
			return "0";
		}		
	} catch (PDOException $e) {
		logError("Error counting active nodes: " . $e->getMessage());
		return "0";
	}
}

function getLastRunTime($script_name) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$stmt = $conn->prepare("SELECT last_run_time FROM last_run WHERE script_name =:script_name");
		$stmt->bindParam(':script_name', $script_name, SQLITE3_TEXT);
		$stmt->execute();
		return $stmt->fetchColumn();
	} catch (PDOException $e) {
		logError("Error getting last run time: " . $e->getMessage());
		return false; 
	}
}

function updateLastRunTime($script_name) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$stmt = $conn->prepare("UPDATE last_run SET last_run_time =:last_run_time WHERE script_name =:script_name");

		$stmt->bindParam(':script_name', $script_name, SQLITE3_TEXT);
		$stmt->bindValue(':last_run_time', time(), SQLITE3_INTEGER);
		$stmt->execute();

		// Check if any rows were affected
		if ($stmt->rowCount() > 0) {
			return true;
		} else {
			$stmt = $conn->prepare("INSERT INTO last_run (script_name, last_run_time) VALUES (:script_name, :last_run_time)");
			$stmt->bindParam(':script_name', $script_name, SQLITE3_TEXT);
			$stmt->bindValue(':last_run_time', time(), SQLITE3_INTEGER);
			$stmt->execute();
			return true;
		}
	} catch (PDOException $e) {
		logError("Error updating last run time: " . $e->getMessage());
		return false; 
	}
}

function createVM($memory,$disk_space,$cpu_cores,$loc) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$stmt = $conn->prepare("SELECT * FROM nodes WHERE loc = :loc AND status = :status");
		$stmt->bindValue(':loc', $loc, PDO::PARAM_STR);
		$stmt->bindValue(':status', 1, PDO::PARAM_INT);
		$stmt->execute();
		$node = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($node) {
			$node_id = $node["node_id"];
			$vncport = $node["lastvnc"]+1;
			$wsport = $node["lastws"]+1;
			$vmnum = $node["lastvm"]+1;
		} else {
			logError("Error finding an available node ($loc).");
			return false; 
		}

		if(!$vmnum) {
			$vmnum="101";
			$vncport="5901";
			$wsport="6901";			
		}
		$vmname = "kvm".$vmnum;
		$password = substr(md5(rand().rand()), 0, 6);
		$encpw = encrypt($password);
		$disk1 = $vmname."-disk1.img";
		$memorymb = $memory * 1024;
				
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /usr/bin/virt-install --name '.$vmname.' --ram '.$memorymb.' --vcpus='.$cpu_cores.' --disk path=/home/kontrolvm/data/'.$disk1.',size='.$disk_space.',format=qcow2,bus=virtio,cache=writeback --network=bridge:br0,model=virtio --cdrom /home/kontrolvm/isos/systemrescue-amd64.iso --os-variant linux2022 --osinfo generic --noautoconsole --graphics vnc,listen=0.0.0.0,port='.$vncport.',password='.$password.',keymap=en-us --hvm --boot uefi');
		$ssh->exec('/bin/rm -rf /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('/bin/touch /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /usr/bin/virsh destroy '.$vmname.'');
		$ssh->exec('sudo /usr/bin/virsh change-media '.$vmname.' sda /home/kontrolvm/isos/systemrescue-amd64.iso --insert --config');
		$ssh->exec('sudo /usr/bin/virsh dumpxml '.$vmname.' --security-info > /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /bin/sed -i -e \'s/<on_reboot>destroy<\/on_reboot>/<on_reboot>restart<\/on_reboot>/g\' /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /bin/sed -i -e \'s/<on_crash>destroy<\/on_crash>/<on_crash>restart<\/on_crash>/g\' /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /bin/sed -i \'/<source bridge=\x27br0\x27\/>/a\ \ \ \ \ \ \ <target dev=\x27'.$vmname.'\x27\/>\' /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /bin/sed -ie \'s/<boot dev=\x27hd\x27\/>/<boot dev=\x27cdrom\x27\/>/g\' /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /usr/bin/virsh define /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /usr/bin/virsh autostart '.$vmname.'');
		$ssh->exec('sudo /usr/bin/virsh start '.$vmname.'');
		$ssh->exec('sudo /bin/sed -ie \'s/<boot dev=\x27hd\x27\/>/<boot dev=\x27cdrom\x27\/>/g\' /home/kontrolvm/xmls/'.$vmname.'.xml');
		$macaddr = $ssh->exec("sudo virsh domiflist ". $vmname ." | awk 'NR==3{print $5}'");
		$network = $ssh->exec("sudo virsh domiflist ". $vmname ." | awk 'NR==3{print $1}'");
		$ssh->exec('/bin/rm -rf /home/kontrolvm/addrs/'.$vmname.'');
		$ssh->exec('/bin/touch /home/kontrolvm/addrs/'.$vmname.'');
		$ssh->exec('sudo /bin/sh /home/kontrolvm/create_console.sh '.$wsport.' '.$vncport.'');

		$data = [':name' => $vmname,':hostname' => $vmname,':status' => 1,':node_id' => $node_id,':loc' => $loc,':cpu_cores' => $cpu_cores,':memory' => $memory,':protected' => 0,':mac_address' => $macaddr,':nic' => 1000,':iow' => 1000,':vncpw' => $encpw,':vncport' => $vncport,':websockify' => $wsport,':network' => $network,':netdriver' => 'virtio',':diskdriver' => 'virtio',':bootorder' => 'cdrom',':created_at' => time(),':last_updated' => time()];
		$stmt = $conn->prepare("INSERT INTO vms (name, hostname, node_id, status, loc, cpu_cores, memory, mac_address, nic, iow, vncpw, vncport, websockify, network, netdriver, diskdriver, bootorder, created_at, last_updated, protected) VALUES (:name,:hostname,:node_id,:status,:loc,:cpu_cores,:memory,:mac_address,:nic,:iow,:vncpw,:vncport,:websockify,:network,:netdriver,:diskdriver,:bootorder,:created_at,:last_updated,:protected)");
		$stmt->execute($data);

		$vm_id = $conn->lastInsertId();	
		$data = [':disk_name' => $disk1,':disk_size' => $disk_space,':vm_id' => $vm_id,':node_id' => $node_id,':last_updated' => time()];
		$stmt = $conn->prepare("INSERT INTO disks (disk_name, disk_size, vm_id, node_id, last_updated) VALUES (:disk_name,:disk_size,:vm_id,:node_id,:last_updated)");
		$stmt->execute($data);

		$data = [':lastvnc' => $vncport,':lastws' => $wsport,':lastvm' => $vmnum,':node_id' => $node_id];
		$stmt = $conn->prepare("UPDATE nodes SET lastvnc =:lastvnc, lastws =:lastws, lastvm =:lastvm WHERE node_id =:node_id");
		$stmt->execute($data);

		return true;
	} catch (PDOException $e) {
		logError("Error creating VM ($vmname): " . $e->getMessage());
		return false; 
	}
}

function restartVM($vm_id,$vmname,$node_id) {
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('nohup sudo /usr/bin/virsh reboot '.$vmname.' > /dev/null 2>&1 &');
		#echo $ssh->getLog();
		$ssh->disconnect();
		return true;
	} catch (PDOException $e) {
		logError("Error restarting VM ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function startVM($vm_id,$vmname,$node_id) {
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('nohup sudo /usr/bin/virsh start '.$vmname.' > /dev/null 2>&1 &');
		#echo $ssh->getLog();
		$ssh->disconnect();
		return true;
	} catch (PDOException $e) {
		logError("Error starting VM ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function stopVM($vm_id,$vmname,$node_id) {
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('nohup sudo /usr/bin/virsh destroy '.$vmname.' > /dev/null 2>&1 &');
		#echo $ssh->getLog();
		$ssh->disconnect();
		return true;
	} catch (PDOException $e) {
		logError("Error stopping VM ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function shutdownVM($vm_id,$vmname,$node_id) {
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('nohup sudo /usr/bin/virsh shutdown '.$vmname.' > /dev/null 2>&1 &');
		#echo $ssh->getLog();
		$ssh->disconnect();
		return true;
	} catch (PDOException $e) {
		logError("Error stopping VM ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function destroyVM($vm_id,$vmname,$websockify,$vncport,$node_id,$confirm) {
	if($confirm = 1) {
		include('config.php');
		$conn = new PDO("sqlite:$db_file_path");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		try {
			$ssh = connectNode($node_id);
			$ssh->exec('sudo /bin/sh /home/kontrolvm/destroyvps.sh '.$vmname.'');
			sleep(5);
			$ssh->exec('sudo /bin/sh /home/kontrolvm/killconsole.sh '.$vncport.'');
			sleep(5);
			$disks = getDisks($vm_id);
			foreach ($disks as $disk) {
				deleteDisk($vm_id,$disk['disk_id'],$disk['disk_name'],$node_id);
			}
			#echo $ssh->getLog();
			$ssh->disconnect();
			$stmt = $conn->prepare("DELETE FROM vms WHERE vm_id =:vm_id");
			$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
			$stmt->execute();
			$stmt = $conn->prepare("DELETE FROM disks WHERE vm_id =:vm_id");
			$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
			$stmt->execute();
			$stmt = $conn->prepare("UPDATE ipv4 SET vmid =:vmid, node =:node, status =:status WHERE vmid =:vm_id");
			$stmt->bindValue(':vmid', '0', SQLITE3_INTEGER);
			$stmt->bindValue(':node', '0', SQLITE3_TEXT);
			$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
			$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
			$stmt->execute();
			$stmt = $conn->prepare("UPDATE ipv6 SET vmid =:vmid, node =:node, status =:status WHERE vmid =:vm_id");
			$stmt->bindValue(':vmid', '0', SQLITE3_INTEGER);
			$stmt->bindValue(':node', '0', SQLITE3_TEXT);
			$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
			$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
			$stmt->execute();
			return true;
		} catch (PDOException $e) {
			logError("Error stopping VM ($vm_id): " . $e->getMessage());
			return false; 
		}
	} else {
		logError("No confirmation ($vm_id): " . $e->getMessage());
		return false;
	}
}

function setCPU($vm_id,$vmname,$cpu,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /usr/bin/virsh setvcpus '.$vmname.' '.$cpu.' --config --maximum');
		$ssh->exec('sudo /usr/bin/virsh setvcpus '.$vmname.' '.$cpu.' --config');
		$ssh->exec('sudo /usr/bin/virsh dumpxml '.$vmname.' --security-info > /home/kontrolvm/xmls/ '.$vmname.'.xml');
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET cpu_cores =:cpu_cores WHERE vm_id =:vm_id");
		$stmt->bindValue(':cpu_cores', $cpu, SQLITE3_INTEGER);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error updating VM IOW ($vm_id): " . $e->getMessage());
		return false; 
	}	
}

function setRAM($vm_id,$vmname,$memory,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /usr/bin/virsh setmaxmem '.$vmname.' '.$memory.'G --config');
		$ssh->exec('sudo /usr/bin/virsh setmem '.$vmname.' '.$memory.'G --config');
		$ssh->exec('sudo /usr/bin/virsh dumpxml '.$vmname.' --security-info > /home/kontrolvm/xmls/ '.$vmname.'.xml');
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET memory =:memory WHERE vm_id =:vm_id");
		$stmt->bindValue(':memory', $memory, SQLITE3_INTEGER);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error updating VM IOW ($vm_id): " . $e->getMessage());
		return false; 
	}	
}

function getDisks($vm_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$sql = "SELECT * FROM disks WHERE vm_id = $vm_id ORDER BY disk_id";
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$disks = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $disks;
	} catch (PDOException $e) {
		logError("Error fetching disk list ($vm_id): " . $e->getMessage());
		return false;
	}
}

function addDisk($vm_id,$vmname,$disk_size,$node_id) {
	$disk_size = (int)$disk_size;
	if($disk_size > 0) {
		include('config.php');
		$conn = new PDO("sqlite:$db_file_path");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		try {
			$stmt = $conn->prepare("SELECT COUNT(*) FROM disks WHERE vm_id =:vm_id");
			$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
			$stmt->execute();
			$count = $stmt->fetchColumn();
			$ssh = connectNode($node_id);
			if($count > 0) {
				$disknum = $count + 1;
				$diskfile = $vmname.'-disk'.$disknum.'.img';
				$file_exists = true;
				while($file_exists) {
					$diskfile = $vmname.'-disk'.$disknum.'.img';
					$checkdisk = $ssh->exec("ls -la /home/kontrolvm/data/$diskfile | wc -l");
					if ($checkdisk == 1) {
						$disknum++;
					} else {
						$file_exists = false;
						$letter = chr(96 + $disknum);
						$volid = "vd".$letter;
						$disk_name = $vmname.'-disk'.$disknum.'.img';
					}
				}
			} else {
				$disk_name = $vmname.'-disk'.$disknum.'.img';
				$volid = 'vda';
			}
			$ssh->exec('/usr/bin/qemu-img create -f qcow2 /home/kontrolvm/data/'.$disk_name.' '.$disk_size.'G');
			$ssh->exec("chmod 0640 /home/kontrolvm/data/$disk_name");
			$ssh->exec("sudo /usr/bin/virsh attach-disk $vmname /home/kontrolvm/data/$disk_name $volid --type disk --cache writeback --config --persistent");
			$ssh->exec("sudo /usr/bin/virsh dumpxml $vmname --security-info > /home/kontrolvm/xmls/$vmname.xml");
			$ssh->exec("sudo /usr/bin/virsh define /home/kontrolvm/xmls/$vmname.xml");
			$ssh->disconnect();

			$stmt = $conn->prepare("INSERT INTO disks (disk_name, disk_size, vm_id, node_id, last_updated) VALUES (:disk_name, :disk_size, :vm_id, :node_id, :last_updated)");
			$stmt->bindValue(':disk_name', "$disk_name", SQLITE3_TEXT);
			$stmt->bindValue(':disk_size', $disk_size, SQLITE3_INTEGER);
			$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
			$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
			$stmt->bindValue(':last_updated', time(), SQLITE3_TEXT);
			$stmt->execute();
			return true;
		} catch (PDOException $e) {
			$error = $e->getMessage();
			logError("Error adding VM disk ($vm_id): ".$error);
			return $error;
		}
	} else {
		$error = "Disk size incorrect.";
		logError("Error adding VM disk ($vm_id): ".$error);
		return $error;
	}
}

function resizeDisk($vm_id,$vmname,$disk_id,$disk_name,$disk_size,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /usr/bin/qemu-img resize /home/kontrolvm/data/'.$disk_name.' '.$disk_size.'G');
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE disks SET disk_size =:disk_size WHERE disk_id =:disk_id");
		$stmt->bindValue(':disk_size', $disk_size, SQLITE3_INTEGER);
		$stmt->bindValue(':disk_id', $disk_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = $e->getMessage();
		logError("Error updating VM disk ($disk_id): ".$error);
		return $error;
	}	
}

function deleteDisk($vm_id,$vmname,$disk_id,$disk_name,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec("sudo /usr/bin/virsh detach-disk $vmname /home/kontrolvm/data/$disk_name --config --persistent");
		$ssh->exec("sudo /usr/bin/virsh dumpxml $vmname --security-info > /home/kontrolvm/xmls/$vmname.xml");
		$ssh->exec("sudo /bin/sh /home/kontrolvm/cleandata.sh $disk_name");
		$ssh->disconnect();

		$stmt = $conn->prepare("DELETE FROM disks WHERE disk_id =:disk_id");
		$stmt->bindValue(':disk_id', $disk_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = $e->getMessage();
		logError("Error deleting VM disk ($disk_id - $disk_name): ".$error);
		return $error;
	}	
}

function setIOW($vm_id,$vmname,$speed,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec('/bin/rm -rf /home/kontrolvm/iow/'.$vmname.'');
		$ssh->exec('echo "virsh blkdeviotune '.$vmname.' vda --write_bytes_sec $(expr 1024 \* 1024 \* '.$speed.')" > /home/kontrolvm/iow/'.$vmname.'');
		$ssh->exec('sudo /bin/sh /home/kontrolvm/iow/'.$vmname.'');
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET iow =:iow WHERE vm_id =:vm_id");
		$stmt->bindValue(':iow', $speed, SQLITE3_INTEGER);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = $e->getMessage();
		logError("Error updating VM IOW ($vm_id): ".$error);
		return $error;
	}	
}

function setNIC($vm_id,$vmname,$nicToChange,$speed,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec('/bin/rm -rf /home/kontrolvm/tc/'.$vmname.'');
		$ssh->exec('echo "/sbin/tc qdisc del dev '.$nicToChange.' root" >> /home/kontrolvm/tc_stop.sh');
		$ssh->exec('echo "/sbin/tc qdisc del dev '.$nicToChange.' ingress" >> /home/kontrolvm/tc_stop.sh');
		$ssh->exec('echo "/sbin/tc qdisc add dev '.$nicToChange.' root" >> /home/kontrolvm/tc/'.$vmname.'');
		$ssh->exec('echo "/sbin/tc qdisc add dev '.$nicToChange.' root handle 1: htb default 1" >> /home/kontrolvm/tc/'.$vmname.'');
		$ssh->exec('echo "/sbin/tc class add dev '.$nicToChange.' parent 1: classid 1:1 htb rate '.$speed.'mbit ceil '.$speed.'mbit burst 15k" >> /home/kontrolvm/tc/'.$vmname.'');
		$ssh->exec('echo "/sbin/tc class add dev '.$nicToChange.' parent 1:1 classid 1:1 htb rate '.$speed.'mbit burst 15k" >> /home/kontrolvm/tc/'.$vmname.'');
		$ssh->exec('echo "/sbin/tc qdisc add dev '.$nicToChange.' parent 1:1 handle 1: sfq perturb 10" >> /home/kontrolvm/tc/'.$vmname.'');
		$ssh->exec('echo "/sbin/tc qdisc add dev '.$nicToChange.' ingress" >> /home/kontrolvm/tc/'.$vmname.'');
		$ssh->exec('echo "/sbin/tc filter add dev '.$nicToChange.' parent ffff: protocol ip u32 match ip src 0.0.0.0/0 police rate '.$speed.'mbit burst 15k mtu 64kb drop flowid :1" >> /home/kontrolvm/tc/'.$vmname.'');
		$sql = "SELECT ipaddress FROM ipv4 WHERE vmid =:vmid";
		$stmt = $conn->prepare($sql);
		$stmt->bindParam(':vmid', $vm_id, PDO::PARAM_INT);
		$stmt->execute();
		$data = $stmt->fetchAll(PDO::FETCH_ASSOC);
		foreach ($data as $row) {
			$ip = $row['ipaddress'];
			$ssh->exec('echo "/sbin/tc filter add dev br0 protocol ip parent 1:0 prio 1 u32 match ip src '.$ip.' flowid 1:'.$speed.'" >> /home/kontrolvm/tc/'.$vmname.'');
		}
		$ssh->exec('sudo /bin/sh /home/kontrolvm/tc_stop.sh');
		$ssh->exec('sudo /bin/sh /home/kontrolvm/tc_start.sh');
		#echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET nic =:nic WHERE vm_id =:vm_id");
		$stmt->bindValue(':nic', $speed, SQLITE3_INTEGER);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error updating VM NIC ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function disableVNC($vm_id,$vmname,$websockify,$vncport,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /bin/sh /home/kontrolvm/killconsole.sh '.$vncport);
		sleep(2);
		$ssh->exec('/bin/touch /home/kontrolvm/disabledvnc/'.$vncport);
		$ssh->exec('sudo /sbin/iptables -A INPUT -p tcp --destination-port '.$vncport.' -j DROP');
		#echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET vncexpire =:vncexpire WHERE vm_id =:vm_id");
		$stmt->bindValue(':vncexpire', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error disabling VM VNC ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function enableVNC($vm_id,$vmname,$websockify,$vncport,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /bin/sh /home/kontrolvm/killconsole.sh '.$vncport);
		sleep(2);
		$ssh->exec('sudo /bin/sh /home/kontrolvm/create_console.sh '.$websockify.' '.$vncport);
		$ssh->exec('/bin/rm -rf /home/kontrolvm/disabledvnc/'.$vncport.'');
		$ssh->exec('sudo /sbin/iptables -D INPUT -p tcp --destination-port '.$vncport.' -j DROP');
		#echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET vncexpire =:vncexpire WHERE vm_id =:vm_id");
		$stmt->bindValue(':vncexpire', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error disabling VM VNC ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function consolePW($vm_id,$vmname,$vncport,$node_id) {
	include('config.php');
	$password = substr(md5(rand().rand()), 0, 8);
	$encpw = encrypt($password);
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /bin/sed -i \'/vnc/c\ \ \ \ <graphics type=\x27vnc\x27 port=\x27'.$vncport.'\x27 autoport=\x27no\x27 listen=\x270.0.0.0\x27 keymap=\x27en-us\x27 passwd=\x27'.$password.'\x27>\' /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /usr/bin/virsh define /home/kontrolvm/xmls/'.$vmname.'.xml');
		#echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET vncpw =:vncpw WHERE vm_id =:vm_id");
		$stmt->bindValue(':vncpw', "$encpw", SQLITE3_TEXT);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error disabling VM VNC ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function mountISO($vm_id,$vmname,$ostemplate,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /usr/bin/virsh attach-disk '.$vmname.' /home/kontrolvm/isos/'.$ostemplate.' sda --type cdrom --mode readonly --persistent');
		$ssh->exec('sudo /usr/bin/virsh change-media '.$vmname.' sda /home/kontrolvm/isos/'.$ostemplate.' --insert --live --config');
		$ssh->exec('sudo /usr/bin/virsh dumpxml '.$vmname.' --security-info > /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /bin/sed -ie \'s/<boot dev=\x27hd\x27\/>/<boot dev=\x27cdrom\x27\/>/g\' /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /usr/bin/virsh define /home/kontrolvm/xmls/'.$vmname.'.xml');
		echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET os_template =:os_template, bootorder =:bootorder WHERE vm_id =:vm_id");
		$stmt->bindValue(':os_template', "$ostemplate", SQLITE3_TEXT);
		$stmt->bindValue(':bootorder', "cdrom", SQLITE3_TEXT);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error mounting ISO ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function unmountISO($vm_id,$vmname,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /usr/bin/virsh change-media '.$vmname.' sda --eject --live');
		$ssh->exec('sudo /usr/bin/virsh change-media '.$vmname.' sda --eject --config');
		$ssh->exec('sudo /usr/bin/virsh change-media '.$vmname.' fda --eject --live');
		$ssh->exec('sudo /usr/bin/virsh change-media '.$vmname.' fda --eject --config');
		$ssh->exec('sudo /usr/bin/virsh detach-disk '.$vmname.' fda --live');
		$ssh->exec('sudo /usr/bin/virsh detach-disk '.$vmname.' fda --config');
		$ssh->exec('sudo /usr/bin/virsh detach-disk '.$vmname.' sda --live');
		$ssh->exec('sudo /usr/bin/virsh detach-disk '.$vmname.' sda --config');
		$ssh->exec('sudo /usr/bin/virsh dumpxml '.$vmname.' --security-info > /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /bin/sed -ie \'s/<boot dev=\x27cdrom\x27\/>/<boot dev=\x27hd\x27\/>/g\' /home/kontrolvm/xmls/'.$vmname.'.xml');
		$ssh->exec('sudo /usr/bin/virsh define /home/kontrolvm/xmls/'.$vmname.'.xml');
		#echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET os_template =:os_template,bootorder =:bootorder WHERE vm_id =:vm_id");
		$stmt->bindValue(':os_template', "kvm", SQLITE3_TEXT);
		$stmt->bindValue(':bootorder', "hd", SQLITE3_TEXT);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error unmounting ISO ($vm_id): " . $e->getMessage());
		return false; 
	}
}

#function diskDriver($vm_id,$vmname,$bus,$node_id) {
#	include('config.php');
#	$conn = new PDO("sqlite:$db_file_path");
#	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
#	try {
#		$ssh = connectNode($node_id);
#		if($bus == 'ide') {
#			$ssh->exec('sudo /bin/sed -i \'/vda/c\ \ \ \ \ \ <target dev=\x27vda\x27\ bus=\x27ide\x27\/>\' /home/kontrolvm/xmls/'.$vmname.'.xml');
#		} else {
#			$ssh->exec('sudo /bin/sed -i \'/vda/c\ \ \ \ \ \ <target dev=\x27vda\x27\ bus=\x27virtio\x27\/>\' /home/kontrolvm/xmls/'.$vmname.'.xml');
#		}
#		$ssh->exec('sudo /usr/bin/virsh define /home/kontrolvm/xmls/'.$vmname.'.xml');		
#		#echo $ssh->getLog();
#		$ssh->disconnect();
#
#		$stmt = $conn->prepare("UPDATE vms SET diskdriver =:diskdriver WHERE vm_id =:vm_id");
#		$stmt->bindValue(':diskdriver', "$bus", SQLITE3_TEXT);
#		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
#		$stmt->execute();
#		return true;
#	} catch (PDOException $e) {
#		logError("Error updating VM disk driver ($vm_id): " . $e->getMessage());
#		return false; 
#	}
#}
#
#function netDriver($vm_id,$vmname,$bus,$node_id) {
#	include('config.php');
#	$conn = new PDO("sqlite:$db_file_path");
#	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
#	try {
#		$ssh = connectNode($node_id);
#		if($bus == 'e1000') {
#			$ssh->exec('sudo /bin/sed -i \'/<model type=\x27virtio\x27\/>/c\ \ \ \ \ \ <model type=\x27e1000\x27\/>\' /home/kontrolvm/xmls/'.$vmname.'.xml');
#		} else {
#			$ssh->exec('sudo /bin/sed -i \'/<model type=\x27e1000\x27\/>/c\ \ \ \ \ \ <model type=\x27virtio\x27\/>\' /home/kontrolvm/xmls/'.$vmname.'.xml');
#		}
#		$ssh->exec('sudo /usr/bin/virsh define /home/kontrolvm/xmls/'.$vmname.'.xml');
#		#echo $ssh->getLog();
#		$ssh->disconnect();
#
#		$stmt = $conn->prepare("UPDATE vms SET netdriver =:netdriver WHERE vm_id =:vm_id");
#		$stmt->bindValue(':netdriver', "$bus", SQLITE3_TEXT);
#		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
#		$stmt->execute();
#		return true;
#	} catch (PDOException $e) {
#		logError("Error updating VM network driver ($vm_id): " . $e->getMessage());
#		return false; 
#	}
#}

function bootOrder($vm_id,$vmname,$boot,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$ssh = connectNode($node_id);
		if($boot == 'hd') {
			$ssh->exec('sudo /bin/sed -ie \'s/<boot dev=\x27cdrom\x27\/>/<boot dev=\x27hd\x27\/>/g\' /home/kontrolvm/xmls/'.$vmname.'.xml');
		} else {
			$ssh->exec('sudo /bin/sed -ie \'s/<boot dev=\x27hd\x27\/>/<boot dev=\x27cdrom\x27\/>/g\' /home/kontrolvm/xmls/'.$vmname.'.xml');
		}
		$ssh->exec('sudo /usr/bin/virsh define /home/kontrolvm/xmls/'.$vmname.'.xml');
		#echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET bootorder =:bootorder WHERE vm_id =:vm_id");
		$stmt->bindValue(':bootorder', "$boot", SQLITE3_TEXT);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error updating VM boot order ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function addCluster($loc, $friendlyname) {
	$loc = trim($loc);
	$friendlyname = trim($friendlyname);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$sql = "SELECT COUNT(*) FROM clusters WHERE loc =':loc'";
	$stmt = $conn->prepare($sql);
	$stmt->bindValue(':loc', "$loc", SQLITE3_TEXT);
	$stmt->execute();
	$count = $stmt->fetchColumn();
	if ($count > 0) {
		$error = "Cluster address exists.";
		return $error;
	} else {
		$stmt = $conn->prepare('INSERT INTO clusters (loc, friendlyname, status, last_updated) VALUES (:loc, :friendlyname, :status, :last_updated)');
	}
	$stmt->bindValue(':loc', "$loc", SQLITE3_TEXT);
	$stmt->bindValue(':friendlyname', "$friendlyname", SQLITE3_TEXT);
	$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
	$stmt->bindValue(':last_updated', time(), SQLITE3_TEXT);

	$result = $stmt->execute();

	if ($result) {
		return true;
	} else {
		$error = "Error inserting cluster: " . $conn->lastErrorMsg();
		return $error;
	}
}

function deleteCluster($clusterid) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("DELETE FROM clusters WHERE clusterid =:clusterid");
		$stmt->bindValue(':clusterid', $clusterid, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error deleting cluster: ". $e->getMessage());
		return false;
	}
}

function enableCluster($clusterid) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("UPDATE clusters SET status =:status WHERE clusterid =:clusterid");
		$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':clusterid', $clusterid, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error updating cluster: ". $e->getMessage());
		return false;
	}
}

function disableCluster($clusterid) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("UPDATE clusters SET status =:status WHERE clusterid =:clusterid");
		$stmt->bindValue(':status', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':clusterid', $clusterid, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error updating cluster: ". $e->getMessage());
		return false;
	}
}

function enableMFA($staff_id,$mfasecret,$mfacode) {
	if(is_int($mfacode)) {
		$google2fa = new Google2FA();
		if ($google2fa->verifyKey($mfasecret, $mfacode, '1')) {
			include('config.php');
			$conn = new PDO("sqlite:$db_file_path");
			$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			try {
				$stmt = $conn->prepare("UPDATE staff SET staff_mfa =:staff_mfa WHERE staff_id =:staff_id");
				$stmt->bindValue(':staff_mfa', "$mfasecret", SQLITE3_TEXT);
				$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
				$stmt->execute();
				return true;
			} catch (PDOException $e) {
				logError("Error updating staff: ". $e->getMessage());
				return false;
			}
		} else {
			logError("Error validating MFA code.");
			return false;
		}
	} else {
		logError("Error MFA missing secret and/or code.");
		return false;
	}
}

function disableMFA($staff_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("UPDATE staff SET staff_mfa =:staff_mfa WHERE staff_id =:staff_id");
		$stmt->bindValue(':staff_mfa', NULL, SQLITE3_TEXT);
		$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error updating staff: ". $e->getMessage());
		return false;
	}
}

function verifyMFA($staff_id,$mfacode) {
	if(is_int($mfacode)) {
		$staff = getStaffDetails($staff_id);
		$google2fa = new Google2FA();
		if ($google2fa->verifyKey($staff['staff_mfa'], $mfacode, '1')) {
			return true;
		} else {
			logError("Error validating MFA code.");
			return false;
		}
	} else {
		logError("Error MFA missing code.");
		return false;
	}
}

function sendPasswordResetEmail($email) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("SELECT staff_id FROM staff WHERE staff_email =:staff_email");
		$stmt->bindValue(':staff_email', "$email", SQLITE3_TEXT);
		$stmt->execute();
		$staff = $stmt->fetchColumn();
		if($staff > "0") {
			$resetToken = bin2hex(random_bytes(16));
			$domain = $_SERVER['HTTP_HOST'];
			$directory = dirname($_SERVER['PHP_SELF']);
			$full_domain = "https://".$domain.$directory;
			$stmt = $conn->prepare("UPDATE staff SET staff_pwreset =:staff_pwreset WHERE staff_email =:staff_email");
			$stmt->bindValue(':staff_pwreset', "$resetToken", SQLITE3_TEXT);
			$stmt->bindValue(':staff_email', "$email", SQLITE3_TEXT);
			$stmt->execute();
			$subject = 'KontrolVM Password Reset';
			$message = "
				<p>Hello,</p>
				<p>You have requested a password reset for your account.</p>
				<p>Please click the following link to reset your password:</p>
				<a href='$full_domain/password_reset.php?token=$resetToken&id=$email'>Reset Password</a>
			";
			if(sendMail($message,$subject,$email)) {
				return true;
			} else {
				return false;
			}
		} else {
			return false;
		}
	} catch (PDOException $e) {
		logError("Error finding staff: ". $e->getMessage());
		return false;
	}
}

function verifyToken($token,$email) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("SELECT staff_id FROM staff WHERE staff_pwreset =:staff_pwreset AND staff_email =:staff_email");
		$stmt->bindValue(':staff_pwreset', "$token", SQLITE3_TEXT);
		$stmt->bindValue(':staff_email', "$email", SQLITE3_TEXT);
		$stmt->execute();
		$active = $stmt->fetchColumn();
		if($active > "0") {
			$domain = $_SERVER['HTTP_HOST'];
			$directory = dirname($_SERVER['PHP_SELF']);
			$full_domain = "https://".$domain.$directory;
			$password = generateRandomString();
			$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
			$stmt = $conn->prepare("UPDATE staff SET staff_password =:staff_password, staff_pwreset =:staff_pwreset WHERE staff_email =:staff_email");
			$stmt->bindValue(':staff_password', "$hashedPassword", SQLITE3_TEXT);
			$stmt->bindValue(':staff_pwreset', ' ', SQLITE3_TEXT);
			$stmt->bindValue(':staff_email', "$email", SQLITE3_TEXT);
			$result = $stmt->execute();
			$subject = 'KontrolVM Password Reset Successful';
			$message = "
				<p>Hello,</p>
				<p>You password reset request was successful.</p>
				<p>Please login with the following password: $password</p>
				<p><i>Please change this password once you <a href='$full_domain'>login</a>.</i></p>
			";
			if(sendMail($message,$subject,$email)) {
				return true;
			} else {
				return false;
			}
		} else {
			return false;
		}
	} catch(PDOException $e) {
		die("Database error: " . $e->getMessage());
	}
	return false;
}

function getLogs($perPage,$offset) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("SELECT * FROM logs ORDER BY created_at DESC LIMIT $perPage OFFSET $offset");
		$stmt->execute();
		$logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $logs;
	} catch (PDOException $e) {
		logError("Error fetching logs: " . $e->getMessage());
		return false;
	}
}

function getLogsTotal() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$totalLogs = $conn->query("SELECT COUNT(*) FROM logs")->fetchColumn();
		return $totalLogs;
	} catch (PDOException $e) {
		logError("Error fetching logs: " . $e->getMessage());
		return false;
	}
}

function backupVM($vm_id,$vmname,$node_id) {
	include('config.php');
	$backup_name = $vmname.'_'.date('Ydmhis');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /home/kontrolvm/backup_vm.sh '.$vmname.' '.$backup_name.' > /dev/null 2>&1 &');
		#echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare('INSERT INTO backups (backup_name, vm_id, node_id, created_at) VALUES (:backup_name, :vm_id, :node_id, :created_at)');
		$stmt->bindValue(':backup_name', "$backup_name.tar.gz", SQLITE3_TEXT);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
		$stmt->bindValue(':created_at', time(), SQLITE3_TEXT);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		logError("Error backing up VM ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function getBackups($vm_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$sql = "SELECT * FROM backups WHERE vm_id = $vm_id ORDER BY backup_id";
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$backups = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $backups;
	} catch (PDOException $e) {
		logError("Error fetching backup list ($vm_id): " . $e->getMessage());
		return false;
	}
}

?>