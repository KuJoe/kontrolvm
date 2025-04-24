<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

if(!defined('AmAllowed')) {
	die('Error 001A');
}
define('KONTROLVM_VERSION', '1.0');
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

function logMessage($message,$staff_id = 0) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare('INSERT INTO logs (log_message,staff_id) VALUES (:log_message,:staff_id)');
		$stmt->bindValue(':log_message', "$message", SQLITE3_TEXT);
		$stmt->bindParam(':staff_id', $staff_id, SQLITE3_INTEGER);
		$result = $stmt->execute();
		return true;
	} catch (PDOException $e) {
		error_log("Error writing log ($message): " . $e->getMessage());
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

function generateMAC($macaddr) {
    if(!preg_match('/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/', $macaddr)) {
        return false;
    }
    $octets = explode(':', $macaddr);
    $newLastOctet = sprintf('%02x', mt_rand(0, 255));
    $octets[5] = $newLastOctet;
    $newmacaddr = implode(':', $octets);
    return $newmacaddr;
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
	if(is_resource($connection)) {
		fclose($connection);
		$ssh = new SSH2($node['ipaddr'], $node['sshport'], 5);
		$key = PublicKeyLoader::load(file_get_contents($node['sshkey']));
		//$ssh->enablePTY();
		$ssh->setTimeout(30);
		$ssh->login($node['sshuser'], $key);
		if($ssh->isConnected()) {
			return $ssh;
		} else {
			$error = "SSH connection failed for $node_id: ".$ssh->getLastError();
			logMessage($error);
			return $error;
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
			$error = "Mailer Error: ".$mail->ErrorInfo;
			logMessage($error);
			return $error;
		}
	} else {
		$error = "Mailer sending error: Please configure the SMTP settings in config.php";
		logMessage($error);
		return $error;
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
		error_log("Database error: " . $e->getMessage());
		die("DB Error");
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
		if($locked) {
			$locked_datetime = DateTime::createFromFormat('Y-m-d H:i:s', $locked);
			$now = new DateTime();
			if($locked_datetime > $now) {
				return true;
			} else {
				return false;
			}
		} else {
			return false;
		}
	} catch(PDOException $e) {
		error_log("Database error: " . $e->getMessage());
		die("DB Error");
	}
	return false;
}

function getStaffRole($staff_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("SELECT staff_role FROM staff WHERE staff_id =:staff_id");
		$stmt->bindParam(':staff_id', $staff_id, SQLITE3_INTEGER);
		$stmt->execute();
		$role = $stmt->fetchColumn();
		return $role;
	} catch(PDOException $e) {
		error_log("Database error: " . $e->getMessage());
		die("DB Error");
	}
	return false;
}

function checkNodeCleaned($node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    try {
        $stmt = $conn->prepare("SELECT COUNT(*) FROM vms WHERE node_id =:node_id");
		$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
		$stmt->execute();
		$count = $stmt->fetchColumn();
    } catch(PDOException $e) {
		$error = "Database error (checkNodeCleaned): " . $e->getMessage();
		logMessage($error);
		return $error;
	}
    return $count > 0 ? false : true;
}

function checkClusterCleaned($cluster) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$stmt = $conn->prepare("SELECT COUNT(*) FROM nodes WHERE cluster =:cluster");
		$stmt->bindValue(':cluster', $cluster, SQLITE3_INTEGER);
		$stmt->execute();
		$count = $stmt->fetchColumn();
	} catch (PDOException $e) {
		$error = "Error counting active nodes: " . $e->getMessage();
		logMessage($error);
		return $error;
	}
    return $count > 0 ? false : true;
}

function createUser($myid,$username,$email) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$password = generateRandomString();
		$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
		$stmt = $conn->prepare('INSERT INTO staff (staff_username, staff_email, staff_password, staff_role) VALUES (:staff_username, :staff_email, :staff_password, :staff_role)');
		$stmt->bindValue(':staff_username', "$username", SQLITE3_TEXT);
		$stmt->bindValue(':staff_email', "$email", SQLITE3_TEXT);
		$stmt->bindValue(':staff_password', "$hashedPassword", SQLITE3_TEXT);
		$stmt->bindValue(':staff_role', '1', SQLITE3_INTEGER);
		$result = $stmt->execute();
		logMessage("User created: $username.",$myid);
		return $password;
	} catch (PDOException $e) {
		$error = "Error creating staff: " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function deleteUser($myid,$staff_id,$confirm) {
	if($confirm) {
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
				$error = "Cannot delete ID 1 account.";
				logMessage($error,$myid);
				return $error;
			}
		} catch (PDOException $e) {
			$error = "Error deleting staff: " . $e->getMessage();
			logMessage($error,$myid);
			return $error;
		}
	} else {
		$error = "No confirmation ($staff_id)";
		logMessage($error,$myid);
		return $error;
	}
}

function updateStaff($myid,$staff_id,$username,$email,$status,$role,$password1,$password2) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		if(!is_null($password2)) {
			if($password1 = $password2) {
				$password = password_hash($password1, PASSWORD_DEFAULT);
				$stmt = $conn->prepare("UPDATE staff SET staff_username =:staff_username, staff_email =:staff_email, staff_active =:staff_active, staff_password =:password, staff_role =:staff_role WHERE staff_id =:staff_id");
				$stmt->bindValue(':staff_username', "$username", SQLITE3_TEXT);
				$stmt->bindValue(':staff_email', "$email", SQLITE3_TEXT);
				$stmt->bindValue(':staff_active', $status, SQLITE3_INTEGER);
				$stmt->bindValue(':password', "$password", SQLITE3_TEXT);
				$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
				$stmt->bindValue(':staff_role', $role, SQLITE3_INTEGER);
				$stmt->execute();
				return true;
			} else {
				$error = "Error updating account ($staff_id): password mismatch";
				logMessage($error,$myid);
				return $error;
			}
		} else {
			$stmt = $conn->prepare("UPDATE staff SET staff_username =:staff_username, staff_email =:staff_email, staff_active =:staff_active, staff_role =:staff_role WHERE staff_id =:staff_id");
			$stmt->bindValue(':staff_username', "$username", SQLITE3_TEXT);
			$stmt->bindValue(':staff_email', "$email", SQLITE3_TEXT);
			$stmt->bindValue(':staff_active', $status, SQLITE3_INTEGER);
			$stmt->bindValue(':staff_id', $staff_id, SQLITE3_INTEGER);
			$stmt->bindValue(':staff_role', $role, SQLITE3_INTEGER);
			$stmt->execute();
			return true;
		}
	} catch (PDOException $e) {
		$error = "Error updating account ($staff_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
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
		$error = "Error fetching staff details: " . $e->getMessage();
		logMessage($error);
		return $error; 
	}
}

function getClusterName($cluster_id) {
	include('config.php');
	try {
		$conn = new PDO("sqlite:$db_file_path");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		$sql = "SELECT friendlyname FROM clusters WHERE cluster_id =:cluster_id";
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':cluster_id', "$cluster_id", SQLITE3_INTEGER);
		$stmt->execute();

		$friendlyname = $stmt->fetchColumn();
		return $friendlyname;

	} catch (PDOException $e) {
		$error = "Error fetching node name: ". $e->getMessage();
		logMessage($error);
		return $error;
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
		$error = "Error fetching node name: ". $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function addNode($myid,$hostname,$ipaddr,$sshport,$rootpw,$cluster) {
	include('config.php');
	try {
		$rootpw = trim($rootpw);
		$ssh = new SSH2($ipaddr, $sshport);
		$ssh->login('root', $rootpw);
		if($ssh->isConnected()) {
			$ssh->setTimeout(60);
			$kversion = $ssh->exec("/usr/bin/cat /home/kontrolvm/conf/kontrolvm.conf");
			if(trim($kversion) !== "kontrolvm_version=".KONTROLVM_VERSION) {
				throw new Exception("KontrolVM not installed or incorrect version.");
			}
			$sshkeypublic = file_get_contents($sshkeypub);
			$kontrolvmip = $_SERVER['SERVER_ADDR'];
			$sshkeypublic = 'from="'.$kontrolvmip.'" '.$sshkeypublic;
			$ssh->exec("echo '$sshkeypublic' >> /home/kontrolvm/.ssh/authorized_keys");
			#$kontrolvm_url = dirname((empty($_SERVER['HTTPS']) ? 'http' : 'https') . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]");
			#$ssh->exec("echo 'kontrolvm_url=$kontrolvm_url' >> /home/kontrolvm/conf/kontrolvm.conf");
			$ssh->disconnect();
		} else {
			throw new Exception("SSH connection with password failed.");
		}
	} catch (Exception $e) {
		$error = "Error adding node: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
	try {
		$conn = new PDO("sqlite:$db_file_path");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$stmt = $conn->prepare('INSERT INTO nodes (hostname, ipaddr, sshport, cluster, sshuser, sshkey, lastvnc, lastws, lastvm, status, last_updated) VALUES (:hostname, :ipaddr, :sshport, :cluster, :sshuser, :sshkey, :lastvnc, :lastws, :lastvm, :status, :last_updated)');
		$stmt->bindValue(':hostname', "$hostname", SQLITE3_TEXT);
		$stmt->bindValue(':ipaddr', "$ipaddr", SQLITE3_TEXT);
		$stmt->bindValue(':sshport', $sshport, SQLITE3_INTEGER);
		$stmt->bindValue(':cluster', $cluster, SQLITE3_INTEGER);
		$stmt->bindValue(':sshuser', "$sshusernow", SQLITE3_TEXT);
		$stmt->bindValue(':sshkey', "$sshkeypriv", SQLITE3_TEXT);
		$stmt->bindValue(':lastvnc', '5901', SQLITE3_INTEGER);
		$stmt->bindValue(':lastws', '6901', SQLITE3_INTEGER);
		$stmt->bindValue(':lastvm', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':last_updated', time(), SQLITE3_TEXT);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error adding node: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
	
}

function deleteNode($myid,$node_id,$confirm) {
	if($confirm) {
		if(checkNodeCleaned($node_id)) {
			include('config.php');
			$conn = new PDO("sqlite:$db_file_path");
			$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			try {
				$stmt = $conn->prepare("DELETE FROM nodes WHERE node_id =:node_id");
				$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
				$stmt->execute();
				return true;
			} catch (PDOException $e) {
				$error = "Error deleting node: ". $e->getMessage();
				logMessage($error,$myid);
				return $error;
			}
		} else {
			$error = "Node has VMs on it ($node_id)";
			logMessage($error,$myid);
			return $error;
		}
	} else {
		$error = "No confirmation ($node_id)";
		logMessage($error,$myid);
		return $error;
	}
}

function updateNode($node_id, $node_data) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$node_data[':node_id'] = $node_id;
	$node_data[':last_updated'] = time();
	$stmt = $conn->prepare("UPDATE nodes SET cpu_cores =:cpu_cores,total_memory =:total_memory,disk_space =:disk_space,make =:make,model =:model,cpu =:cpu,vms =:vms,os_version =:os_version,kernel_version =:kernel_version,libvirt_version =:libvirt_version,last_updated =:last_updated WHERE node_id =:node_id");
	if($stmt->execute($node_data)) {
		return true;
	} else {
		$error = "Error updating node: " . $conn->lastErrorMsg();
		logMessage($error);
		return $error;
	}
}

function editNode($myid,$node_id, $node_data) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$node_data[':node_id'] = $node_id;
	$node_data[':last_updated'] = time();
	$stmt = $conn->prepare("UPDATE nodes SET hostname =:hostname,ipaddr =:ipaddr,sshport =:sshport,status =:status,lastvm =:lastvm,lastvnc =:lastvnc,lastws =:lastws,cluster =:cluster,last_updated =:last_updated WHERE node_id =:node_id");

	if($stmt->execute($node_data)) {
		return true;
	} else {
		$error = "Error editing node: " . $conn->lastErrorMsg();
		logMessage($error,$myid);
		return $error;
	}
}

function getNetworks($node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare('SELECT * FROM networks WHERE node_id =:node_id ORDER BY net_name ASC');
		$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
		$stmt->execute();
		$networks = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $networks;
	} catch (PDOException $e) {
		$error = "Error fetching cluster list: " . $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function addNetwork($myid,$node_id,$net_name) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare('INSERT INTO networks (net_name, node_id, last_updated) VALUES (:net_name, :node_id, :last_updated)');
		$stmt->bindValue(':net_name', "$net_name", SQLITE3_TEXT);
		$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
		$stmt->bindValue(':last_updated', time(), SQLITE3_TEXT);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error adding network ($node_id - $net_name): ".$e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function deleteNetwork($myid,$node_id, $net_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare('DELETE FROM networks WHERE net_id =:net_id');
		$stmt->bindValue(':net_id', $net_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error deleting network ($node_id - $net_id): ".$e->getMessage();
		logMessage($error,$myid);
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
		$error = "Error fetching node details: " . $e->getMessage();
		logMessage($error);
		return $error; 
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
		$error = "Error fetching node details: " . $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function getClusterDetails($cluster_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$sql = "SELECT * FROM clusters WHERE cluster_id =:cluster_id";
		$stmt = $conn->prepare($sql);
		$stmt->bindParam(':cluster_id', $cluster_id, SQLITE3_INTEGER);
		$stmt->execute();
		$cluster = $stmt->fetch(PDO::FETCH_ASSOC);
		return $cluster; 
	} catch (PDOException $e) {
		$error = "Error fetching cluster details: " . $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function updateKontrolVMNode($node_id) {
	include('config.php');
	$latestVersion = @file_get_contents('https://kontrolvm.com/version');

	$ssh = connectNode($node_id);
	$version = "kontrolvm_version=".trim($latestVersion);
	$file = "/home/kontrolvm/conf/kontrolvm.conf";
	$kversion = $ssh->exec("echo '$version' > $file");
	#$ssh->exec("/usr/bin/curl -fsSL https://kontrolvm.com//update.sh | bash");
	#echo $ssh->getLog();
	$ssh->disconnect();
	return;
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
		$error = "Error fetching node details: " . $e->getMessage();
		logMessage($error);
		return $error;
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

		if($unit == "G") {
			$ram = $value;
		} elseif($unit == "M") {
			$ram = $value / 1024;
		} elseif($unit == "K") {
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
		$kontrolvm_version = $ssh->exec('cat /home/kontrolvm/conf/kontrolvm.conf | tail -c +19');
		
		$ssh->disconnect();
		$node_data = [':cpu_cores' => $cpu,':total_memory' => $ram,':disk_space' => $total_disk,':make' => $make,':model' => $model,':cpu' => $cpumodel,':vms' => $vms,':os_version' => $os_version,':kernel_version' => $kernel_version,':libvirt_version' => $libvirt_version];
		updateNode($node_id, $node_data);
		return true;
	} catch (Exception $e) {
		$error = "Error connecting to $node_id: " . $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function getServerList($status) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		if($status == "all") {
			$sql = "SELECT * FROM nodes ORDER BY hostname ASC";
		} else {
			$sql = "SELECT * FROM nodes WHERE status = $status ORDER BY hostname ASC";
		}
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$servers = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $servers;
	} catch (PDOException $e) {
		$error = "Error fetching server list: " . $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function getClusters($status) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if($status == "all") {
		$sql = "SELECT * FROM clusters ORDER BY friendlyname ASC";
		} else {
			$sql = "SELECT * FROM clusters WHERE status = $status ORDER BY friendlyname ASC";
		}
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$clusters = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $clusters;
	} catch (PDOException $e) {
		$error = "Error fetching cluster list: " . $e->getMessage();
		logMessage($error);
		return $error;
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
		$error = "Error fetching user list: " . $e->getMessage();
		logMessage($error);
		return $error;
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
		$error = "Error stopping VM ($vm_id): " . $e->getMessage();
		logMessage($error);
		return $error;
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
		$error = "Error fetching VM list: " . $e->getMessage();
		logMessage($error);
		return $error;
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
		$error = "Error fetching ISOs list: " . $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function addISOs($myid,$download,$friendlyname) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$path_parts = parse_url($download);
	$path_parts = explode("/", $path_parts['path']);
	foreach ($path_parts as $part) {
		if(preg_match('/\.iso$/', $part)) {
			$filename = $part;
		}
	}
	$localFile = "wget_isos.sh";
	$wgetCommand = '/usr/bin/wget -O /home/kontrolvm/isos/'.$filename.' '.$download;
    file_put_contents($localFile, $wgetCommand . PHP_EOL, FILE_APPEND | LOCK_EX) !== false;
	$rundl = downloadISOs($localFile);
	if($rundl === true) {
		$stmt = $conn->prepare('INSERT INTO ostemplates (filename, friendlyname, status, added) VALUES (:filename, :friendlyname, :status, :added)');
		$stmt->bindValue(':filename', "$filename", SQLITE3_TEXT);
		$stmt->bindValue(':friendlyname', "$friendlyname", SQLITE3_TEXT);
		$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':added', time(), SQLITE3_TEXT); 
		$result = $stmt->execute();
		
		if($result) {
			return true;
		} else {
			$error = "Error adding ISO: " . $conn->lastErrorMsg();
			logMessage($error,$myid);
			return $error;
		}
	} else {
		$error = "Error downloading ISO";
		logMessage($error,$myid);
		return $error;
	}
}

function deleteISO($myid,$template_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$stmt = $conn->prepare('DELETE FROM ostemplates WHERE template_id =:template_id');
	$stmt->bindValue(':template_id', $template_id, SQLITE3_INTEGER);
	$result = $stmt->execute();
	if($result) {
		return true;
	} else {
		$error = "Error deleting ISO ($template_id): " . $conn->lastErrorMsg();
		logMessage($error,$myid);
		return $error;
	}
}

function downloadISOs($localFile) {
	$localFileContents = file_get_contents($localFile);
 	$escapedContents = escapeshellarg($localFileContents);
	$remoteCommand = "echo " . $escapedContents . " > /home/kontrolvm/isos/wget_isos.sh";
	$servers = getServerList('1');
	foreach ($servers as $server) {
		try {
			$node_id = $server['node_id'];
			$ssh = connectNode($node_id);
			$ssh->exec($remoteCommand);
			$ssh->exec('/usr/bin/sh /home/kontrolvm/isos/wget_isos.sh  > /dev/null 2>&1 &', true);
			sleep(1);
			#echo $ssh->getLog();
			$ssh->disconnect();
		} catch (PDOException $e) {
			$error = "Error downloading ISOs ($node_id): " . $e->getMessage();
			logMessage($error);
			return $error;
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
		$error = "Error fetching IPs: " . $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function getAvailableIPs($cluster,$version) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if($version == '4') {
			$sql = "SELECT * FROM ipv4 WHERE cluster =:cluster AND status = '1' AND vmid = '0' ORDER BY ipaddress ASC";
		} else {
			$sql = "SELECT * FROM ipv6 WHERE cluster =:cluster AND status = '1' AND vmid = '0' ORDER BY ipaddress ASC";
		}
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':cluster', $cluster, SQLITE3_INTEGER);
		$stmt->execute();
		$ips = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $ips;
	} catch (PDOException $e) {
		$error = "Error fetching IP list: " . $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function getVMIPs($vmid,$version) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if($version == '4') {
			$sql = "SELECT * FROM ipv4 WHERE vmid =:vmid ORDER BY ipaddress ASC";
		} else {
			$sql = "SELECT * FROM ipv6 WHERE vmid =:vmid ORDER BY ipaddress ASC";
		}
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':vmid', $vmid, SQLITE3_INTEGER);
		$stmt->execute();
		$ips = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $ips;
	} catch (PDOException $e) {
		$error = "Error fetching IPv$version list for VM ($vmid): " . $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function addIPs($myid,$ipaddress, $gwip, $cluster) {
	$ipaddress = trim($ipaddress);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	if(filter_var($ipaddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		$stmt = $conn->prepare("SELECT COUNT(*) FROM ipv4 WHERE ipaddress =:ipaddress");
		$stmt->bindValue(':ipaddress', "$ipaddress", SQLITE3_TEXT);
		$stmt->execute();
		$count = $stmt->fetchColumn();
		if($count > 0) {
			$error = "IP address exists.";
			logMessage($error,$myid);
			return $error;
		} else {
			$stmt = $conn->prepare('INSERT INTO ipv4 (ipaddress, gwip, node, cluster, vmid, status, notes, last_updated) VALUES (:ipaddress, :gwip, :node, :cluster, :vmid, :status, :notes, :last_updated)');
		}
	} else {
		$checkip = $ipaddress."::";
		if(filter_var($checkip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			$sql = 'SELECT COUNT(*) FROM ipv6 WHERE ipaddress =:ipaddress';
			$stmt = $conn->prepare($sql);
			$stmt->bindValue(':ipaddress', "$ipaddress", SQLITE3_TEXT);
			$stmt->execute();
			$count = $stmt->fetchColumn();
			if($count > 0) {
				$error = "IP address exists.";
				logMessage($error,$myid);
				return $error;
			} else {
				$stmt = $conn->prepare('INSERT INTO ipv6 (ipaddress, gwip, node, cluster, vmid, status, notes, last_updated) VALUES (:ipaddress, :gwip, :node, :cluster, :vmid, :status, :notes, :last_updated)');
			}
		} else {
			$error = "Not a valid IP address.";
			logMessage($error,$myid);
			return $error;
		}
	}
	$stmt->bindValue(':ipaddress', "$ipaddress", SQLITE3_TEXT);
	$stmt->bindValue(':gwip', "$gwip", SQLITE3_TEXT);
	$stmt->bindValue(':node', '0', SQLITE3_TEXT);
	$stmt->bindValue(':cluster', "$cluster", SQLITE3_INTEGER);
	$stmt->bindValue(':vmid', '0', SQLITE3_INTEGER);
	$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
	$stmt->bindValue(':notes', ' ', SQLITE3_TEXT);
	$stmt->bindValue(':last_updated', time(), SQLITE3_TEXT);

	$result = $stmt->execute();

	if($result) {
		return true;
	} else {
		$error = "Error inserting data: " . $conn->lastErrorMsg();
		logMessage($error,$myid);
		return $error;
	}
}

function deleteIP($myid,$ip_id,$ipaddress) {
	$ipaddress = trim($ipaddress);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if(filter_var($ipaddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$sql = "DELETE FROM ipv4 WHERE ip_id =:ip_id";
		} else {
			$sql = "DELETE FROM ipv6 WHERE ip_id =:ip_id";
		}
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':ip_id', $ip_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error deleting row: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function enableIP($myid,$ip_id,$ipaddress) {
	$ipaddress = trim($ipaddress);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if(filter_var($ipaddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$sql = "UPDATE ipv4 SET status =:status WHERE ip_id =:ip_id";
		} else {
			$sql = "UPDATE ipv6 SET status =:status WHERE ip_id =:ip_id";
		}
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':ip_id', $ip_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error updating row: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function disableIP($myid,$ip_id,$ipaddress) {
	$ipaddress = trim($ipaddress);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if(filter_var($ipaddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$sql = "UPDATE ipv4 SET status =:status WHERE ip_id =:ip_id";
		} else {
			$sql = "UPDATE ipv6 SET status =:status WHERE ip_id =:ip_id";
		}
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':status', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':ip_id', $ip_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error updating row: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function attachIP($myid,$vmid,$ip_id,$node,$version) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		# For future configurations (Issues #11 and #13) 
		#$ssh = connectNode($node_id);
		#$ssh->exec('echo "'.$ip.'" >> /home/kontrol/addrs/kvm'.$vpsid.'');
		#$ssh->exec('sh /home/kontrol/buildnet.sh');
		#$ssh->exec('echo "0" > /home/kontrol/traffic/'.$ip.'');
		#if($version == '4') {
		#	$sql = "UPDATE ipv4 SET status =:status,vmid =:vmid,node =:node WHERE ip_id =:ip_id";
		#	$ssh->exec('sudo /sbin/iptables -D FORWARD -s '.$ip.'; sudo /sbin/iptables -D FORWARD -d '.$ip.'');
		#	$ssh->exec('echo "'.$ip.'" >> /home/kontrol/ip4');
		#} else {
		#	$ip2 = inet_ntop(inet_pton($ip));
		#	$sql = "UPDATE ipv6 SET status =:status,vmid =:vmid,node =:node WHERE ip_id =:ip_id";
		#	$ssh->exec('sudo /sbin/ip6tables -D FORWARD -s '.$ip2.'; sudo /sbin/ip6tables -D FORWARD -d '.$ip2.'');
		#	$ssh->exec('echo "'.$ip2.'" >> /home/kontrol/ip6');
		#}
		##echo $ssh->getLog();
		#$ssh->disconnect();
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':status', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':vmid', $vmid, SQLITE3_INTEGER);
		$stmt->bindValue(':node', $node, SQLITE3_INTEGER);
		$stmt->bindValue(':ip_id', $ip_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error updating row: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function detachIP($myid,$ip_id,$version) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		if($version == '4') {
			$sql = "UPDATE ipv4 SET status =:status,vmid =:vmid,node =:node WHERE ip_id =:ip_id";
		} else {
			$sql = "UPDATE ipv6 SET status =:status,vmid =:vmid,node =:node WHERE ip_id =:ip_id";
		}
		$stmt = $conn->prepare($sql);
		$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':vmid', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':node', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':ip_id', $ip_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error updating row: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function getTotalCPU() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$stmt = $conn->prepare("SELECT SUM(cpu_cores) AS total_cores FROM nodes");
		$stmt->execute();
		$result = $stmt->fetch(PDO::FETCH_ASSOC);
		$total_cores = $result['total_cores'];
		if($total_cores) {
			return $total_cores;
		} else {
			return "0";
		}
	} catch (PDOException $e) {
		$error = "Error calculating total CPU cores: " . $e->getMessage();
		return "0";
	}
}

function getTotalDisk() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$stmt = $conn->prepare("SELECT SUM(disk_space) AS total_disk FROM nodes");
		$stmt->execute();
		$result = $stmt->fetch(PDO::FETCH_ASSOC);
		$total_disk = $result['total_disk'];
		if($total_disk) {
			return $total_disk;
		} else {
			return "0";
		}
	} catch (PDOException $e) {
		$error = "Error calculating total disk space: " . $e->getMessage();
		return "0";
	}
}

function getTotalRAM() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$stmt = $conn->prepare("SELECT SUM(total_memory) AS total_ram FROM nodes");
		$stmt->execute();
		$result = $stmt->fetch(PDO::FETCH_ASSOC);
		$total_ram = $result['total_ram'];
		if($total_ram) {
			return $total_ram;
		} else {
			return "0";
		}
	} catch (PDOException $e) {
		$error = "Error calculating total RAM: " . $e->getMessage();
		return "0";
	}
}

function getTotalVMs() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$stmt = $conn->prepare("SELECT SUM(vms) AS total_vms FROM nodes");
		$stmt->execute();
		$result = $stmt->fetch(PDO::FETCH_ASSOC);
		$total_vms = $result['total_vms'];
		if($total_vms) {
			return $total_vms;
		} else {
			return "0";
		}
	} catch (PDOException $e) {
		$error = "Error calculating total VMs: " . $e->getMessage();
		return "0";
	}
}

function getTotalNodes() {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
	try {
		$stmt = $conn->prepare("SELECT COUNT(*) FROM nodes WHERE status = 1");
		$stmt->execute();
		$count = $stmt->fetchColumn();
		if($count) {
			return $count;
		} else {
			return "0";
		}		
	} catch (PDOException $e) {
		$error = "Error counting active nodes: " . $e->getMessage();
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
		$error = "Error getting last run time: " . $e->getMessage();
		logMessage($error);
		return $error;
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
		if($stmt->rowCount() > 0) {
			return true;
		} else {
			$stmt = $conn->prepare("INSERT INTO last_run (script_name, last_run_time) VALUES (:script_name, :last_run_time)");
			$stmt->bindParam(':script_name', $script_name, SQLITE3_TEXT);
			$stmt->bindValue(':last_run_time', time(), SQLITE3_INTEGER);
			$stmt->execute();
			return true;
		}
	} catch (PDOException $e) {
		$error = "Error updating last run time: " . $e->getMessage();
		logMessage($error);
		return $error;
	}
}

function createVM($myid,$memory,$disk_space,$cpu_cores,$cluster) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$stmt = $conn->prepare("SELECT * FROM nodes WHERE cluster = :cluster AND status = :status ORDER BY vms ASC LIMIT 1");
		$stmt->bindValue(':cluster', $cluster, SQLITE3_INTEGER);
		$stmt->bindValue(':status', 1, SQLITE3_INTEGER);
		$stmt->execute();
		$node = $stmt->fetch(PDO::FETCH_ASSOC);
		if($node) {
			$node_id = $node["node_id"];
			$vncport = $node["lastvnc"]+1;
			$wsport = $node["lastws"]+1;
			$vmnum = $node["lastvm"]+1;
		} else {
			$error = "Error finding an available node ($cluster).";
			logMessage($error,$myid);
			return $error;
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
		$nic_name = $vmname."_1";
		$memorymb = $memory * 1024;
		$timenow = time();
				
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /usr/bin/virt-install --name '.$vmname.' --ram '.$memorymb.' --vcpus='.$cpu_cores.' --disk path=/home/kontrolvm/data/'.$disk1.',size='.$disk_space.',format=qcow2,bus=virtio,cache=writeback --network=bridge:virbr0,model=virtio --cdrom /home/kontrolvm/isos/systemrescue-amd64.iso --os-variant linux2022 --osinfo generic --noautoconsole --graphics vnc,listen=0.0.0.0,port='.$vncport.',password='.$password.',keymap=en-us --hvm --boot uefi');
		$ssh->exec('/usr/bin/rm -rf /home/kontrolvm/xmls/'.$vmname.'.xml');
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
		$ssh->exec('/usr/bin/rm -rf /home/kontrolvm/addrs/'.$vmname.'');
		$ssh->exec('/bin/touch /home/kontrolvm/addrs/'.$vmname.'');
		$ssh->exec('sudo /bin/sh /home/kontrolvm/create_console.sh '.$wsport.' '.$vncport.'');

		$data = [':name' => $vmname,':hostname' => $vmname,':status' => 1,':node_id' => $node_id,':cluster' => $cluster,':cpu_cores' => $cpu_cores,':memory' => $memory,':protected' => 0,':mac_address' => $macaddr,':nic' => 1000,':iow' => 1000,':vncpw' => $encpw,':vncport' => $vncport,':websockify' => $wsport,':netdriver' => 'virtio',':diskdriver' => 'virtio',':bootorder' => 'cdrom',':created_at' => $timenow,':last_updated' => $timenow];
		$stmt = $conn->prepare("INSERT INTO vms (name, hostname, node_id, status, cluster, cpu_cores, memory, mac_address, nic, iow, vncpw, vncport, websockify, netdriver, diskdriver, bootorder, created_at, last_updated, protected) VALUES (:name,:hostname,:node_id,:status,:cluster,:cpu_cores,:memory,:mac_address,:nic,:iow,:vncpw,:vncport,:websockify,:netdriver,:diskdriver,:bootorder,:created_at,:last_updated,:protected)");
		$stmt->execute($data);

		$vm_id = $conn->lastInsertId();	
		$data = [':disk_name' => $disk1,':disk_size' => $disk_space,':vm_id' => $vm_id,':node_id' => $node_id,':last_updated' => $timenow];
		$stmt = $conn->prepare("INSERT INTO disks (disk_name, disk_size, vm_id, node_id, last_updated) VALUES (:disk_name,:disk_size,:vm_id,:node_id,:last_updated)");
		$stmt->execute($data);

		$data = [':lastvnc' => $vncport,':lastws' => $wsport,':lastvm' => $vmnum,':node_id' => $node_id];
		$stmt = $conn->prepare("UPDATE nodes SET lastvnc =:lastvnc, lastws =:lastws, lastvm =:lastvm WHERE node_id =:node_id");
		$stmt->execute($data);
		
		$data = [':nic_name' => $nic_name,':mac_address' => $macaddr,':vm_id' => $vm_id,':node_id' => $node_id,':last_updated' => $timenow];
		$stmt = $conn->prepare('INSERT INTO nics (nic_name, mac_address, vm_id, node_id, last_updated) VALUES (:nic_name, :mac_address, :vm_id, :node_id, :last_updated)');
		$stmt->execute($data);

		return true;
	} catch (PDOException $e) {
		$error = "Error creating VM ($vmname): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function editVM($myid,$vm_id,$vm_data) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$vm_data[':vm_id'] = $vm_id;
	$vm_data[':last_updated'] = time();
	$stmt = $conn->prepare("UPDATE vms SET name =:name,hostname =:hostname,notes =:notes,mac_address =:mac_address,vncpw =:vncpw,vncport =:vncport,websockify =:websockify,cluster =:cluster,status =:status,protected =:protected,last_updated =:last_updated WHERE vm_id =:vm_id");

	if($stmt->execute($vm_data)) {
		return true;
	} else {
		$error = "Error editing VM: " . $conn->lastErrorMsg();
		logMessage($error,$myid);
		return $error;
	}
}

function restartVM($myid,$vm_id,$vmname,$node_id) {
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('nohup sudo /usr/bin/virsh reboot '.$vmname.' > /dev/null 2>&1 &', true);
		#echo $ssh->getLog();
		$ssh->disconnect();
		return true;
	} catch (PDOException $e) {
		$error = "Error restarting VM ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function startVM($myid,$vm_id,$vmname,$node_id) {
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('nohup sudo /usr/bin/virsh start '.$vmname.' > /dev/null 2>&1 &', true);
		#echo $ssh->getLog();
		$ssh->disconnect();
		return true;
	} catch (PDOException $e) {
		$error = "Error starting VM ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function stopVM($myid,$vm_id,$vmname,$node_id) {
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('nohup sudo /usr/bin/virsh destroy '.$vmname.' > /dev/null 2>&1 &', true);
		#echo $ssh->getLog();
		$ssh->disconnect();
		return true;
	} catch (PDOException $e) {
		$error = "Error stopping VM ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function shutdownVM($myid,$vm_id,$vmname,$node_id) {
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('nohup sudo /usr/bin/virsh shutdown '.$vmname.' > /dev/null 2>&1 &', true);
		#echo $ssh->getLog();
		$ssh->disconnect();
		return true;
	} catch (PDOException $e) {
		$error = "Error stopping VM ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function destroyVM($myid,$vm_id,$vmname,$websockify,$vncport,$node_id,$confirm) {
	if($confirm) {
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
				deleteDisk($vm_id,$vmname,$disk['disk_id'],$disk['disk_name'],$node_id);
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
			$error = "Error stopping VM ($vm_id): " . $e->getMessage();
			logMessage($error,$myid);
			return $error;
		}
	} else {
		$error = "No confirmation ($vm_id)";
		logMessage($error,$myid);
		return $error;
	}
}

function importVMs($myid,$node_id) {
	$node = getNodeDetails($node_id);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$ssh = connectNode($node_id);
		$vm_list = $ssh->exec("sudo virsh list --all | tail -n +3 | awk '{print $2}'");
		$vm_names = explode("\n", trim($vm_list));
		foreach ($vm_names as $vm_name) {
			if(empty($vm_name)) continue;
			$stmt = $conn->prepare("SELECT COUNT(*) FROM vms WHERE name=:name");
			$stmt->bindParam(':name', $vm_name);
			$stmt->execute();
			$count = $stmt->fetchColumn();
			if($count > 0) {
				continue; // Skip to the next VM
			}			
			$cpu_cores = $ssh->exec("sudo virsh dominfo ". escapeshellarg($vm_name) ." | grep 'CPU(s)' | awk '{print $2}'");
			$memory = $ssh->exec("sudo virsh dominfo ". escapeshellarg($vm_name) ." | grep 'Max memory' | awk '{print $3}'");
			$memory = trim($memory) / 1024 / 1024;
			
			$vncport = $ssh->exec("sudo virsh dumpxml ". escapeshellarg($vm_name) ." | grep vnc | awk '{print $3}'");
			preg_match("/port='(\d+)'/", $vncport, $matches);
			$vncport = $matches['1'];
			$websockify = $vncport + 1000;
			
			$vncpw = $ssh->exec("sudo virsh dumpxml ". escapeshellarg($vm_name) ." | grep vnc | awk '{print $7}'");
			if(!$vncpw) {
				preg_match("/passwd='(.*?)'/", $vncpw, $matches);
				$vncpw = $matches['1'];
				$vncpw = encrypt($vncpw);
			} else {
				$vncpw = " ";
			}
			
			$diskdriver = $ssh->exec("sudo virsh dumpxml ". escapeshellarg($vm_name) ." | grep 'vda' | awk '{print $3}'");
			preg_match("/bus='(.*?)'/", $diskdriver, $matches);
			$diskdriver = $matches['1'];
			if(empty($diskdriver)) {
				$diskdriver = $ssh->exec("sudo virsh dumpxml ". escapeshellarg($vm_name) ." | grep 'sda' | awk '{print $3}'");
				preg_match("/bus='(.*?)'/", $diskdriver, $matches);
				$diskdriver = $matches['1'];
			}
			
			$bootorder = $ssh->exec("sudo virsh dumpxml ". escapeshellarg($vm_name) ." | grep 'boot dev' | awk '{print $2}'");
			preg_match("/dev='(.*?)'/", $bootorder, $matches);
			$bootorder = $matches['1'];
			$netdriver = $ssh->exec("sudo virsh domiflist ". escapeshellarg($vm_name) ." | awk 'NR==3{print $4}'");
			$created_at = time();
							
			$vm_data = [
				'node_id' => $node_id,
				'name' => "$vm_name",
				'hostname' => "$vm_name",
				'status' => "1",
				'cluster' => $node['cluster'],
				'cpu_cores' => $cpu_cores,
				'memory' => $memory,
				'vncport' => $vncport,
				'vncpw' => "$vncpw",
				'websockify' => $websockify,
				'netdriver' => "$netdriver",
				'diskdriver' => "$diskdriver",
				'bootorder' => "$bootorder",
				'created_at' => $created_at
			];
			

			// Insert or update the VM data in the database
			$sql = "INSERT OR REPLACE INTO vms (
						node_id, name, hostname, status, cluster, cpu_cores, memory, vncport, vncpw, websockify, netdriver, diskdriver, bootorder, created_at
					) VALUES (
						:node_id,:name,:hostname,:status,:cluster,:cpu_cores,:memory,:vncport,:vncpw,:websockify,:netdriver,:diskdriver,:bootorder,:created_at
					)";
			$stmt = $conn->prepare($sql);
			$stmt->execute($vm_data);
		}
	} catch (Exception $e) {
		$error = "Error updating VM list: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
	$conn = null;
	return true;
}

function setCPU($myid,$vm_id,$vmname,$cpu,$node_id) {
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
		$error = "Error updating VM IOW ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}	
}

function setRAM($myid,$vm_id,$vmname,$memory,$node_id) {
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
		$error = "Error updating VM IOW ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}	
}

function getDisks($vm_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$stmt = $conn->prepare("SELECT * FROM disks WHERE vm_id = $vm_id ORDER BY disk_id ASC");
		$stmt->execute();
		$disks = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $disks;
	} catch (PDOException $e) {
		$error = "Error fetching disk list ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function addDisk($myid,$vm_id,$vmname,$disk_size,$node_id) {
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
					if($checkdisk == 1) {
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
			$error = "Error adding VM disk ($vm_id): ".$e->getMessage();
			logMessage($error,$myid);
			return $error;
		}
	} else {
		$error = "Error adding VM disk ($vm_id): Disk size incorrect.";
		logMessage($error,$myid);
		return $error;
	}
}

function resizeDisk($myid,$vm_id,$vmname,$disk_id,$disk_name,$disk_size,$node_id) {
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
		$error = "Error updating VM disk ($disk_id): ".$e->getMessage();
		logMessage($error,$myid);
		return $error;
	}	
}

function deleteDisk($myid,$vm_id,$vmname,$disk_id,$disk_name,$node_id) {
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
		$error = "Error deleting VM disk ($disk_id - $disk_name): ".$e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function getNICs($vm_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$stmt = $conn->prepare("SELECT * FROM nics WHERE vm_id = $vm_id ORDER BY nic_id ASC");
		$stmt->execute();
		$nics = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $nics;
	} catch (PDOException $e) {
		$error = "Error fetching NIC list ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function addNIC($myid,$vm_id, $vmname, $network, $macaddr, $node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$newmacaddr = generateMAC($macaddr);
	$nicCount = count(getNICs($vm_id));
	$nic_name = $vmname."_".$nicCount+1;
	try {
		$ssh = connectNode($node_id);
		$output = $ssh->exec('sudo /usr/bin/virsh attach-interface '.$vmname.' --type bridge --source '.$network.' --mac '.$newmacaddr.' --target '.$nic_name.' --model virtio --config --live');
		if(strpos($output, "domain is not running") !== false) {
			$ssh->exec('sudo /usr/bin/virsh attach-interface '.$vmname.' --type bridge --source '.$network.' --mac '.$newmacaddr.' --target '.$nic_name.' --model virtio --config');
		}
		$ssh->exec('sudo /usr/bin/virsh dumpxml '.$vmname.' --security-info > /home/kontrolvm/xmls/'.$vmname.'.xml');
		#echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare('INSERT INTO nics (nic_name, mac_address, vm_id, node_id, last_updated) VALUES (:nic_name, :mac_address, :vm_id, :node_id, :last_updated)');
		$stmt->bindValue(':nic_name', "$nic_name", SQLITE3_TEXT);
		$stmt->bindValue(':mac_address', "$newmacaddr", SQLITE3_TEXT);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
		$stmt->bindValue(':last_updated', time(), SQLITE3_TEXT);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error adding VM NIC ($vmname): ".$e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function deleteNIC($myid,$node_id, $vmname, $nic_id, $macaddr) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /usr/bin/virsh detach-interface '.$vmname.' --type bridge --mac '.$macaddr.' --config --live --persistent');
		$ssh->exec('sudo /usr/bin/virsh dumpxml '.$vmname.' --security-info > /home/kontrolvm/xmls/'.$vmname.'.xml');
		echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare('DELETE FROM nics WHERE nic_id =:nic_id');
		$stmt->bindValue(':nic_id', $nic_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error deleting VM NIC ($nic_id - $vmname): ".$e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function setIOW($myid,$vm_id,$vmname,$speed,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec('/usr/bin/rm -rf /home/kontrolvm/iow/'.$vmname.'');
		$ssh->exec('echo "virsh blkdeviotune '.$vmname.' vda --write_bytes_sec $(expr 1024 \* 1024 \* '.$speed.')" > /home/kontrolvm/iow/'.$vmname.'');
		$ssh->exec('sudo /bin/sh /home/kontrolvm/iow/'.$vmname.'');
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET iow =:iow WHERE vm_id =:vm_id");
		$stmt->bindValue(':iow', $speed, SQLITE3_INTEGER);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error updating VM IOW ($vm_id): ".$e->getMessage();
		logMessage($error,$myid);
		return $error;
	}	
}

function setNIC($myid,$vm_id,$vmname,$nicToChange,$speed,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec('/usr/bin/rm -rf /home/kontrolvm/tc/'.$vmname.'');
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
		$error = "Error updating VM NIC ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function disableVNC($myid,$vm_id,$vmname,$websockify,$vncport,$node_id) {
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
		$error = "Error disabling VM VNC ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function enableVNC($myid,$vm_id,$vmname,$websockify,$vncport,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /bin/sh /home/kontrolvm/killconsole.sh '.$vncport);
		sleep(2);
		$ssh->exec('sudo /bin/sh /home/kontrolvm/create_console.sh '.$websockify.' '.$vncport);
		$ssh->exec('/usr/bin/rm -rf /home/kontrolvm/disabledvnc/'.$vncport.'');
		$ssh->exec('sudo /sbin/iptables -D INPUT -p tcp --destination-port '.$vncport.' -j DROP');
		#echo $ssh->getLog();
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET vncexpire =:vncexpire WHERE vm_id =:vm_id");
		$stmt->bindValue(':vncexpire', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error disabling VM VNC ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function consolePW($myid,$vm_id,$vmname,$vncport,$node_id) {
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
		$error = "Error disabling VM VNC ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function mountISO($myid,$vm_id,$vmname,$ostemplate,$node_id) {
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
		$error = "Error mounting ISO ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function unmountISO($myid,$vm_id,$vmname,$node_id) {
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
		$error = "Error unmounting ISO ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

#function diskDriver($myid,$vm_id,$vmname,$bus,$node_id) {
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
#		$error = "Error updating VM disk driver ($vm_id): " . $e->getMessage();
#		logMessage($error,$myid);
#		return $error;
#	}
#}
#
#function netDriver($myid,$vm_id,$vmname,$bus,$node_id) {
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
#		$error = "Error updating VM network driver ($vm_id): " . $e->getMessage();
#		logMessage($error,$myid);
#		return $error; 
#	}
#}

function bootOrder($myid,$vm_id,$vmname,$boot,$node_id) {
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
		$error = "Error updating VM boot order ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function addCluster($myid,$friendlyname) {
	$friendlyname = trim($friendlyname);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$stmt = $conn->prepare('INSERT INTO clusters (friendlyname, deployment, status, last_updated) VALUES (:friendlyname, :deployment, :status, :last_updated)');
	$stmt->bindValue(':friendlyname', "$friendlyname", SQLITE3_TEXT);
	$stmt->bindValue(':deployment', '1', SQLITE3_INTEGER);
	$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
	$stmt->bindValue(':last_updated', time(), SQLITE3_TEXT);
	$result = $stmt->execute();
	if($result) {
		return true;
	} else {
		$error = "Error inserting cluster: " . $conn->lastErrorMsg();
		logMessage($error,$myid);
		return $error;
	}
}

function editCluster($myid,$cluster_id, $cluster_data) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$cluster_data[':cluster_id'] = $cluster_id;
	$cluster_data[':last_updated'] = time();
	$stmt = $conn->prepare("UPDATE clusters SET friendlyname =:friendlyname,deployment =:deployment,last_updated =:last_updated WHERE cluster_id =:cluster_id");
	if($stmt->execute($cluster_data)) {
		return true;
	} else {
		$error = "Error editing cluster: " . $conn->lastErrorMsg();
		logMessage($error,$myid);
		return $error;
	}
}

function deleteCluster($myid,$cluster_id,$confirm) {
	if($confirm) {
		if(checkClusterCleaned($cluster_id)) {
			include('config.php');
			$conn = new PDO("sqlite:$db_file_path");
			$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			try {
				$stmt = $conn->prepare("DELETE FROM clusters WHERE cluster_id =:cluster_id");
				$stmt->bindValue(':cluster_id', $cluster_id, SQLITE3_INTEGER);
				$stmt->execute();
				return true;
			} catch (PDOException $e) {
				$error = "Error deleting cluster: ". $e->getMessage();
				logMessage($error,$myid);
			return $error;
			}
		} else {
			$error = "Cluster has nodes assigned to it ($cluster_id)";
			logMessage($error,$myid);
			return $error;
		}
	} else {
		$error = "No confirmation ($cluster_id)";
		logMessage($error,$myid);
		return $error;
	}
}

function enableCluster($myid,$cluster_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("UPDATE clusters SET status =:status WHERE cluster_id =:cluster_id");
		$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':cluster_id', $cluster_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error updating cluster: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function disableCluster($myid,$cluster_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$stmt = $conn->prepare("UPDATE clusters SET status =:status WHERE cluster_id =:cluster_id");
		$stmt->bindValue(':status', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':cluster_id', $cluster_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error updating cluster: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function enableMFA($myid,$staff_id,$mfasecret,$mfacode) {
	if(is_int($mfacode)) {
		$google2fa = new Google2FA();
		if($google2fa->verifyKey($mfasecret, $mfacode, '1')) {
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
				$error = "Error updating staff: ". $e->getMessage();
				logMessage($error,$myid);
				return $error;
			}
		} else {
			$error = "Error validating MFA code.";
			logMessage($error,$myid);
			return $error;
		}
	} else {
		$error = "Error MFA missing secret and/or code.";
		logMessage($error,$myid);
		return $error;
	}
}

function disableMFA($myid,$staff_id) {
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
		$error = "Error updating staff: ". $e->getMessage();
		logMessage($error,$myid);
		return $error;
	}
}

function verifyMFA($staff_id,$mfacode) {
	if(is_int($mfacode)) {
		$staff = getStaffDetails($staff_id);
		$google2fa = new Google2FA();
		if($google2fa->verifyKey($staff['staff_mfa'], $mfacode, '1')) {
			return true;
		} else {
			$error = "Error validating MFA code.";
			logMessage($error);
			return $error;
		}
	} else {
		$error = "Error MFA missing code.";
		logMessage($error);
		return $error;
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
		$error = "Error finding staff: ". $e->getMessage();
		logMessage($error);
		return $error;
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
		error_log("Database error: " . $e->getMessage());
		die("DB Error");
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
		$error = "Error fetching logs: " . $e->getMessage();
		logMessage($error);
		return $error; 
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
		$error = "Error fetching logs: " . $e->getMessage();
		logMessage($error);
		return $error; 
	}
}

function backupVM($myid,$vm_id,$vm_name,$node_id) {
	include('config.php');
	$backup_name = $vm_name.'_'.date('Ydmhis');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$ssh = connectNode($node_id);
		$backup_tmpdir = $ssh->exec("/usr/bin/test -d /home/kontrolvm/backups_tmp/$vm_name;echo $?");
		if($backup_tmpdir == 1) {
			$ssh->exec('sudo /home/kontrolvm/backup_vm.sh '.$vm_name.' '.$backup_name.' > /dev/null 2>&1 &', true);
			#echo $ssh->getLog();
			$ssh->disconnect();

			$stmt = $conn->prepare('INSERT INTO backups (backup_name, vm_id, node_id, status, created_at) VALUES (:backup_name, :vm_id, :node_id, "0", :created_at)');
			$stmt->bindValue(':backup_name', "$backup_name.tar.gz", SQLITE3_TEXT);
			$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
			$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
			$stmt->bindValue(':created_at', time(), SQLITE3_TEXT);
			$stmt->execute();
			return true;
		} else {
			$error = "Error starting VM restore: Backup or restore is already running.";
			logMessage($error,$myid);
			return $error;
		}
	} catch (PDOException $e) {
		$error = "Error backing up VM ($vm_id): " . $e->getMessage();
		logMessage($error,$myid);
		return $error; 
	}
}

function deleteBackup($myid,$vm_id,$backup_name,$backup_id,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$ssh->exec("/usr/bin/rm -rf /home/kontrolvm/kvm_backups/$backup_name");
		$ssh->disconnect();

		$stmt = $conn->prepare("DELETE FROM backups WHERE backup_id =:backup_id");
		$stmt->bindValue(':backup_id', $backup_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		$error = "Error deleting VM backup ($backup_id - $backup_name): " . $e->getMessage();
		logMessage($error,$myid);
		return $error; 
	}	
}

function getBackups($vm_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$sql = "SELECT * FROM backups WHERE vm_id = $vm_id ORDER BY backup_id ASC";
		$stmt = $conn->prepare($sql);
		$stmt->execute();
		$backups = $stmt->fetchAll(PDO::FETCH_ASSOC);
		return $backups;
	} catch (PDOException $e) {
		$error = "Error fetching backup list ($vm_id): " . $e->getMessage();
		logMessage($error);
		return $error; 
	}
}

function getBackupInfo($vm_name,$backup_name,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$backup_tmpdir = $ssh->exec("/usr/bin/test -d /home/kontrolvm/backups_tmp/$vm_name;echo $?");
		if($backup_tmpdir == 1) {
			$backup_size = $ssh->exec("/usr/bin/stat -c '%s' /home/kontrolvm/kvm_backups/$backup_name | awk '{printf \"%.2f MB\", \$1 / (1024 * 1024)}'");
			#echo $ssh->getLog();
			$ssh->disconnect();
			$stmt = $conn->prepare("UPDATE backups SET backup_size =:backup_size,status ='1' WHERE backup_name =:backup_name");
			$stmt->bindValue(':backup_size', $backup_size, SQLITE3_INTEGER);
			$stmt->bindValue(':backup_name', "$backup_name", SQLITE3_TEXT);
			$stmt->execute();
		}
		return true;
	} catch (PDOException $e) {
		$error = "Error fetching node details: " . $e->getMessage();
		logMessage($error);
		return $error; 
	}
}

function restoreVM($myid,$backup_name,$vm_name,$vnc_port,$vm_id,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {
		$ssh = connectNode($node_id);
		$backup_tmpdir = $ssh->exec("/usr/bin/test -d /home/kontrolvm/backups_tmp/$vm_name;echo $?");
		if($backup_tmpdir == 1) {
			$ssh->exec('sudo /usr/bin/virsh destroy '.$vm_name.'');
			$ssh->exec('sudo /usr/bin/virsh undefine '.$vm_name.'');
			$ssh->exec('sudo /usr/bin/virsh undefine '.$vm_name.' --nvram');
			$ssh->exec('sudo /usr/bin/virsh destroy '.$vm_name.'');
			$disks = getDisks($vm_id);
			foreach ($disks as $disk) {
				$diskname = $disk['disk_name'];
				$ssh->exec("sudo /bin/sh /home/kontrolvm/cleandata.sh $diskname");
			}
			$ssh->exec('sudo /home/kontrolvm/restore_vm.sh '.$backup_name.' '.$vm_name.' '.$vnc_port.' > /dev/null 2>&1 &', true);
			#echo $ssh->getLog();
			$ssh->disconnect();
			return true;
		} else {
			$error = "Error starting VM restore: Backup or restore is already running.";
			logMessage($error,$myid);
			return $error; 
		}
	} catch (PDOException $e) {
		$error = "Error starting VM restore: " . $e->getMessage();
		logMessage($error,$myid);
		return $error;  
	}
}

function checkVersion($ver = 0) {
	if($ver === 0) {
		$latestVersion = @file_get_contents('https://kontrolvm.com/version');
	}
	$localVersion = KONTROLVM_VERSION;

    if($latestVersion === false) {
        $error = "ERROR: Failed to fetch remote file.";
		logMessage($error);
		return $error;  
    }
	
	if(!is_numeric($latestVersion) || !is_numeric($localVersion)) {
        $error = "ERROR: Both remote and local content must be numeric.";
		logMessage($error);
		return $error; 
    }

	if((float)$latestVersion === (float)$localVersion) {
        return true;
    } else {
        return false;
    }
}

?>