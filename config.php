<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

//
// !! Important settings
//

// SQLite3 Database File
$db_file_path = "../kontrolvm.db";

// SSH Settings
$sshusernow = "kontrolvm";
$sshkeypriv = "../kontrolvm";
$sshkeypub = "../kontrolvm.pub";

// Encrypt/Decrypt Key
$cryptkey = "a-random-string";

//
// Optional settings
//

// SMTP Settings
//$smtp_server = "localhost";
//$smtp_port = "587";
//$smtp_user = "noreply@example.com";
//$smtp_password = "password";
//$smtp_tls = true;
//$smtp_sender = "noreply@example.com";

// Cloudflare Turnstile Keys (https://developers.cloudflare.com/turnstile/)
//$sitekey = "";
//$secretkey = "";

//
// End of settings
//
?>