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

function getRealUserIp() {
	switch(true){
		case (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) : return $_SERVER['HTTP_CF_CONNECTING_IP'];
		case (!empty($_SERVER['HTTP_X_REAL_IP'])) : return $_SERVER['HTTP_X_REAL_IP'];
		case (!empty($_SERVER['HTTP_CLIENT_IP'])) : return $_SERVER['HTTP_CLIENT_IP'];
		case (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) : return $_SERVER['HTTP_X_FORWARDED_FOR'];
		default : return $_SERVER['REMOTE_ADDR'];
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
			error_log("SSH connection failed for $node_id: $error");
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
		die("Database error: " . $e->getMessage());
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
		error_log("Error creating staff: " . $e->getMessage());
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
				error_log("Cannot delete ID 1 account.");
				return false;
			}
		} catch (PDOException $e) {
			error_log("Error deleting staff: " . $e->getMessage());
			return false; 
		}
	} else {
		error_log("No confirmation ($staff_id): " . $e->getMessage());
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
				error_log("Error updating account ($staff_id): password mismatch");
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
		error_log("Error updating account ($staff_id): " . $e->getMessage());
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
		error_log("Error fetching staff details: " . $e->getMessage());
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
		error_log("Error fetching node name: ". $e->getMessage());
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
		error_log("Error fetching node name: ". $e->getMessage());
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
			error_log("Error deleting node: ". $e->getMessage());
			return false;
		}
	} else {
		error_log("No confirmation ($node_id): " . $e->getMessage());
		return false;
	}
}

function updateNode($node_id, $cpu_cores, $total_memory, $disk_space, $make, $model, $cpu, $vms, $os_version, $kernel_version, $libvirt_version) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$last_updated = time();
	$sql = "UPDATE nodes SET 
				cpu_cores =:cpu_cores,
				total_memory =:total_memory,
				disk_space =:disk_space,
				make =:make,
				model =:model,
				cpu =:cpu,
				vms =:vms,
				os_version =:os_version,
				kernel_version =:kernel_version,
				libvirt_version =:libvirt_version,
				last_updated =:last_updated
			WHERE node_id =:node_id";

	$stmt = $conn->prepare($sql);

	$stmt->bindParam(':cpu_cores', $cpu_cores, SQLITE3_INTEGER);
	$stmt->bindParam(':total_memory', $total_memory, SQLITE3_INTEGER);
	$stmt->bindParam(':disk_space', $disk_space, SQLITE3_INTEGER);
	$stmt->bindValue(':make', "$make", SQLITE3_TEXT);
	$stmt->bindValue(':model', "$model", SQLITE3_TEXT);
	$stmt->bindValue(':cpu', "$cpu", SQLITE3_TEXT);
	$stmt->bindParam(':vms', $vms, SQLITE3_INTEGER);
	$stmt->bindValue(':os_version', "$os_version", SQLITE3_TEXT);
	$stmt->bindValue(':kernel_version', "$kernel_version", SQLITE3_TEXT);
	$stmt->bindValue(':libvirt_version', "$libvirt_version", SQLITE3_TEXT);
	$stmt->bindValue(':last_updated', "$last_updated", SQLITE3_TEXT);
	$stmt->bindParam(':node_id', $node_id, SQLITE3_INTEGER);

	if ($stmt->execute()) {
		return true;
	} else {
		$error = "Error updating node: " . $conn->lastErrorMsg();
		return $error;
	}
}

function editNode($node_id, $hostname, $ipaddr, $sshport, $status, $lastvm, $lastvnc, $lastws, $loc) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$last_updated = time();
	$sql = "UPDATE nodes SET 
				hostname =:hostname,
				ipaddr =:ipaddr,
				sshport =:sshport,
				status =:status,
				lastvm =:lastvm,
				lastvnc =:lastvnc,
				lastws =:lastws,
				loc =:loc,
				last_updated =:last_updated 
			WHERE node_id =:node_id";

	$stmt = $conn->prepare($sql);
	
	$stmt->bindValue(':hostname', "$hostname", SQLITE3_TEXT);
	$stmt->bindValue(':ipaddr', "$ipaddr", SQLITE3_TEXT);
	$stmt->bindValue(':sshport', $sshport, SQLITE3_INTEGER);
	$stmt->bindValue(':last_updated', "$last_updated", SQLITE3_TEXT);
	$stmt->bindParam(':status', $status, SQLITE3_INTEGER);
	$stmt->bindParam(':lastvm', $lastvm, SQLITE3_INTEGER);
	$stmt->bindParam(':lastvnc', $lastvnc, SQLITE3_INTEGER);
	$stmt->bindParam(':lastws', $lastws, SQLITE3_INTEGER);
	$stmt->bindValue(':loc', "$loc", SQLITE3_TEXT);
	$stmt->bindParam(':node_id', $node_id, SQLITE3_INTEGER);

	if ($stmt->execute()) {
		return true;
	} else {
		$error = "Error updating node: " . $conn->lastErrorMsg();
		return $error;
	}
}

function editVM($vm_id, $name, $hostname, $disk1, $disk_space1, $notes, $mac_address, $vncpw, $vncport, $websockify, $loc, $status, $protected) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$encpw = encrypt($vncpw);
	$last_updated = time();
	$sql = "UPDATE vms SET
				name =:name,
				hostname =:hostname,
				ip_address =:ipaddr,
				status =:status,
				protected =:protected,
				disk1 =:disk1,
				disk_space1 =:disk_space1,
				mac_address =:mac_address,
				notes =:notes,
				vncpw =:vncpw,
				vncport =:vncport,
				websockify =:websockify,
				loc =:loc,
				last_updated =:last_updated
			WHERE vm_id =:vm_id";

	$stmt = $conn->prepare($sql);
	$stmt->bindValue(':name', "$name", SQLITE3_TEXT);
	$stmt->bindValue(':hostname', "$hostname", SQLITE3_TEXT);
	$stmt->bindParam(':status', $status, SQLITE3_INTEGER);
	$stmt->bindParam(':protected', $protected, SQLITE3_INTEGER);
	$stmt->bindValue(':disk1', "$disk1", SQLITE3_TEXT);
	$stmt->bindParam(':disk_space1', $disk_space1, SQLITE3_INTEGER);
	$stmt->bindValue(':mac_address', "$mac_address", SQLITE3_TEXT);
	$stmt->bindValue(':notes', "$notes", SQLITE3_TEXT);
	$stmt->bindValue(':vncpw', "$encpw", SQLITE3_TEXT);
	$stmt->bindParam(':vncport', $vncport, SQLITE3_INTEGER);
	$stmt->bindParam(':websockify', $websockify, SQLITE3_INTEGER);
	$stmt->bindValue(':loc', "$loc", SQLITE3_TEXT);
	$stmt->bindValue(':last_updated', "$last_updated", SQLITE3_TEXT);
	$stmt->bindParam(':vm_id', $vm_id, SQLITE3_INTEGER);

	if ($stmt->execute()) {
		return true;
	} else {
		$error = "Error updating node: " . $conn->lastErrorMsg();
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
		error_log("Error fetching node details: " . $e->getMessage());
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
		error_log("Error fetching node details: " . $e->getMessage());
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
		error_log("Error fetching node details: " . $e->getMessage());
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
		
		updateNode($node_id, $cpu, $ram, $total_disk, $make, $model, $cpumodel, $vms, $os_version, $kernel_version, $libvirt_version);
		return true;
	} catch (Exception $e) {
		error_log("Error connecting to $node_id: " . $e->getMessage());
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
		error_log("Error fetching server list: " . $e->getMessage());
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
		error_log("Error fetching cluster list: " . $e->getMessage());
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
		error_log("Error fetching user list: " . $e->getMessage());
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
		error_log("Error stopping VM ($vm_id): " . $e->getMessage());
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
		error_log("Error fetching VM list: " . $e->getMessage());
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
		error_log("Error fetching ISOs list: " . $e->getMessage());
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
			sleep(5);
			#echo $ssh->getLog();
			$ssh->disconnect();
		} catch (PDOException $e) {
			error_log("Error downloading ISO ($node_id): " . $e->getMessage());
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
		error_log("Error fetching IPs: " . $e->getMessage());
		return false;
	}
}

function addIPs($ipaddress, $gwip, $loc) {
	$ipaddress = trim($ipaddress);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$last_updated = time();
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
			$stmt = $conn->prepare('INSERT INTO ipv4 (ipaddress, gwip, node, loc, vmid, status, notes, last_updated) VALUES (:ipaddress, :gwip, :node, :loc, :vmid, :status, :notes, :last_updated)');
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
				$stmt = $conn->prepare('INSERT INTO ipv6 (ipaddress, gwip, node, loc, vmid, status, notes, last_updated) VALUES (:ipaddress, :gwip, :node, :loc, :vmid, :status, :notes, :last_updated)');
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
	$stmt->bindValue(':notes', ' ', SQLITE3_INTEGER);
	$stmt->bindValue(':last_updated', "$last_updated", SQLITE3_TEXT); 

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
		error_log("Error deleting row: ". $e->getMessage());
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
		error_log("Error updating row: ". $e->getMessage());
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
		error_log("Error updating row: ". $e->getMessage());
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
		error_log("Error calculating total CPU cores: " . $e->getMessage());
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
		error_log("Error calculating total disk space: " . $e->getMessage());
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
		error_log("Error calculating total RAM: " . $e->getMessage());
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
		error_log("Error calculating total VMs: " . $e->getMessage());
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
		error_log("Error counting active nodes: " . $e->getMessage());
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
		error_log("Error getting last run time: " . $e->getMessage());
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
		error_log("Error updating last run time: " . $e->getMessage());
		return false; 
	}
}

function createVM($memory,$disk_space1,$cpu_cores,$loc) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	try {	
		$sql = "SELECT * FROM nodes WHERE loc =:loc AND status =:status";
		$stmt = $conn->prepare($sql);
		$stmt->bindParam(':loc', $loc, SQLITE3_TEXT);
		$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
		$stmt->execute();
		$node = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($node) {
			$node_id = $node["node_id"];
			$vncport = $node["lastvnc"]+1;
			$wsport = $node["lastws"]+1;
			$vmnum = $node["lastvm"]+1;
		} else {
			error_log("Error finding an available node: " . $e->getMessage());
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
		$created_at = time();
		$memorymb = $memory * 1024;
				
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /usr/bin/virt-install --name '.$vmname.' --ram '.$memorymb.' --vcpus='.$cpu_cores.' --disk path=/home/kontrolvm/data/'.$disk1.',size='.$disk_space1.',format=raw,bus=virtio,cache=writeback --network=bridge:br0,model=virtio --cdrom /home/kontrolvm/isos/systemrescue-amd64.iso --os-variant linux2022 --osinfo detect=on,require=off --noautoconsole --graphics vnc,listen=0.0.0.0,port='.$vncport.',password='.$password.',keymap=en-us --hvm --boot uefi');
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
		
		$stmt = $conn->prepare("INSERT INTO vms (name, hostname, node_id, status, loc, cpu_cores, memory, disk1, disk_space1, ipv4, ipv6, mac_address, nic, iow, vncpw, vncport, websockify, network, netdriver, diskdriver, bootorder, created_at, last_updated, protected) 
												VALUES (:name,:hostname,:node_id,:status,:loc,:cpu_cores,:memory,:disk1,:disk_space1,:ipv4,:ipv6,:mac_address,:nic,:iow,:vncpw,:vncport,:websockify,:network,:netdriver,:diskdriver,:bootorder,:created_at,:last_updated,:protected)");
		$stmt->bindValue(':name', "$vmname", SQLITE3_TEXT);
		$stmt->bindValue(':hostname', "$vmname", SQLITE3_TEXT);
		$stmt->bindValue(':status', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
		$stmt->bindValue(':loc', "$loc", SQLITE3_TEXT);
		$stmt->bindValue(':cpu_cores', $cpu_cores, SQLITE3_INTEGER);
		$stmt->bindValue(':memory', $memory, SQLITE3_INTEGER);
		$stmt->bindValue(':disk1', "$disk1", SQLITE3_TEXT);
		$stmt->bindValue(':disk_space1', $disk_space1, SQLITE3_INTEGER);
		$stmt->bindValue(':ipv4', "1", SQLITE3_INTEGER);
		$stmt->bindValue(':ipv6', '1', SQLITE3_INTEGER);
		$stmt->bindValue(':protected', '0', SQLITE3_INTEGER);
		$stmt->bindValue(':mac_address', "$macaddr", SQLITE3_TEXT);
		$stmt->bindValue(':nic', '1000', SQLITE3_INTEGER);
		$stmt->bindValue(':iow', '1000', SQLITE3_INTEGER);
		$stmt->bindValue(':vncpw', "$encpw", SQLITE3_TEXT);
		$stmt->bindValue(':vncport', $vncport, SQLITE3_INTEGER);
		$stmt->bindValue(':websockify', $wsport, SQLITE3_INTEGER);
		$stmt->bindValue(':network', "$network", SQLITE3_TEXT);
		$stmt->bindValue(':netdriver', "virtio", SQLITE3_TEXT);
		$stmt->bindValue(':diskdriver', "virtio", SQLITE3_TEXT);
		$stmt->bindValue(':bootorder', "cdrom", SQLITE3_TEXT);
		$stmt->bindValue(':created_at', "$created_at", SQLITE3_TEXT);
		$stmt->bindValue(':last_updated', "$created_at", SQLITE3_TEXT);
		$stmt->execute();
		
		$stmt = $conn->prepare("UPDATE nodes SET lastvnc =:lastvnc, lastws =:lastws, lastvm =:lastvm WHERE node_id =:node_id");
		$stmt->bindValue(':lastvnc', $vncport, SQLITE3_INTEGER);
		$stmt->bindValue(':lastws', $wsport, SQLITE3_INTEGER);
		$stmt->bindValue(':lastvm', $vmnum, SQLITE3_INTEGER);
		$stmt->bindValue(':node_id', $node_id, SQLITE3_INTEGER);
		$stmt->execute();
			
		return true;
	} catch (PDOException $e) {
		error_log("Error creating VM ($vmname): " . $e->getMessage());
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
		error_log("Error restarting VM ($vm_id): " . $e->getMessage());
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
		error_log("Error starting VM ($vm_id): " . $e->getMessage());
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
		error_log("Error stopping VM ($vm_id): " . $e->getMessage());
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
		error_log("Error stopping VM ($vm_id): " . $e->getMessage());
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
			#echo $ssh->getLog();
			$ssh->disconnect();
			$stmt = $conn->prepare("DELETE FROM vms WHERE vm_id =:vm_id");
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
			error_log("Error stopping VM ($vm_id): " . $e->getMessage());
			return false; 
		}
	} else {
		error_log("No confirmation ($vm_id): " . $e->getMessage());
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
		$ssh->exec('sudo /usr/bin/virsh dumpxml '.$vmname.' --security-info > /usr/local/wyvern/xmls/ '.$vmname.'.xml');
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET cpu_cores =:cpu_cores WHERE vm_id =:vm_id");
		$stmt->bindValue(':cpu_cores', $cpu, SQLITE3_INTEGER);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		error_log("Error updating VM IOW ($vm_id): " . $e->getMessage());
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
		$ssh->exec('sudo /usr/bin/virsh dumpxml '.$vmname.' --security-info > /usr/local/wyvern/xmls/ '.$vmname.'.xml');
		$ssh->disconnect();

		$stmt = $conn->prepare("UPDATE vms SET memory =:memory WHERE vm_id =:vm_id");
		$stmt->bindValue(':memory', $memory, SQLITE3_INTEGER);
		$stmt->bindValue(':vm_id', $vm_id, SQLITE3_INTEGER);
		$stmt->execute();
		return true;
	} catch (PDOException $e) {
		error_log("Error updating VM IOW ($vm_id): " . $e->getMessage());
		return false; 
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
		error_log("Error updating VM IOW ($vm_id): " . $e->getMessage());
		return false; 
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
		error_log("Error updating VM NIC ($vm_id): " . $e->getMessage());
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
		error_log("Error disabling VM VNC ($vm_id): " . $e->getMessage());
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
		error_log("Error disabling VM VNC ($vm_id): " . $e->getMessage());
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
		error_log("Error disabling VM VNC ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function mountISO($vm_id,$vmname,$ostemplate,$node_id) {
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
		$ssh = connectNode($node_id);
		$ssh->exec('sudo /usr/bin/virsh attach-disk '.$vmname.' /home/kontrolvm/isos/'.$ostemplate.' sda --type cdrom --mode readonly');
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
		error_log("Error mounting ISO ($vm_id): " . $e->getMessage());
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
		error_log("Error unmounting ISO ($vm_id): " . $e->getMessage());
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
#		error_log("Error updating VM disk driver ($vm_id): " . $e->getMessage());
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
#		error_log("Error updating VM network driver ($vm_id): " . $e->getMessage());
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
		error_log("Error updating VM boot order ($vm_id): " . $e->getMessage());
		return false; 
	}
}

function addCluster($loc, $friendlyname) {
	$loc = trim($loc);
	$friendlyname = trim($friendlyname);
	include('config.php');
	$conn = new PDO("sqlite:$db_file_path");
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$last_updated = time();
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
	$stmt->bindValue(':last_updated', "$last_updated", SQLITE3_TEXT); 

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
		error_log("Error deleting cluster: ". $e->getMessage());
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
		error_log("Error updating cluster: ". $e->getMessage());
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
		error_log("Error updating cluster: ". $e->getMessage());
		return false;
	}
}

function enableMFA($staff_id,$mfasecret,$mfacode) {
	if(is_int($mfacode) OR isset($mfasecret)) {
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
				error_log("Error updating staff: ". $e->getMessage());
				return false;
			}
		} else {
			error_log("Error validating MFA code.");
			return false;
		}
	} else {
		error_log("Error MFA missing secret and/or code.");
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
		error_log("Error updating staff: ". $e->getMessage());
		return false;
	}
}

?>