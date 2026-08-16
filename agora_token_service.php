<?php
/**
 * Agora RTC Token Builder (v006 - Standard compliant)
 * Generates dynamic RTC Tokens for Voice & Video calls.
 *
 * Based on: https://github.com/AgoraIO/Tools/tree/master/DynamicKey/AgoraDynamicKey/php
 *
 * CRITICAL: appCertificate must be hex2bin() decoded before HMAC-SHA256.
 */

class Message {
    public $salt;
    public $ts;
    public $privileges;

    public function __construct() {
        $this->salt = rand(1, 99999999);
        $this->ts   = time() + 24 * 3600;
        $this->privileges = [];
    }

    public function packContent() {
        $buf  = pack('V', $this->salt);
        $buf .= pack('V', $this->ts);
        $buf .= pack('v', count($this->privileges));
        foreach ($this->privileges as $k => $v) {
            $buf .= pack('v', $k);
            $buf .= pack('V', $v);
        }
        return $buf;
    }
}

class AccessToken {
    const kJoinChannel        = 1;
    const kPublishAudioStream = 2;
    const kPublishVideoStream = 3;
    const kPublishDataStream  = 4;

    public $appID;
    public $appCertificate; // Hex string (32-byte hex = 16 raw bytes)
    public $channelName;
    public $uid;            // String: '0' or numeric string
    public $message;

    public function __construct($appID, $appCertificate, $channelName, $uid) {
        $this->appID          = $appID;
        $this->appCertificate = $appCertificate;
        $this->channelName    = $channelName;
        $this->uid            = is_int($uid) ? ($uid === 0 ? '' : (string)$uid) : (string)$uid;
        $this->message        = new Message();
    }

    public function addPrivilege($privilege, $expireTs) {
        $this->message->privileges[$privilege] = $expireTs;
        return $this;
    }

    public function build() {
        $msg = $this->message->packContent();

        // The string to sign: appID + channelName + uid + packed message
        $val = $this->appID . $this->channelName . $this->uid . $msg;

        // IMPORTANT: appCertificate is a hex string — must be decoded to binary before signing
        $key = hex2bin($this->appCertificate);
        $sig = hash_hmac('sha256', $val, $key, true);

        // CRC32 over channel name and uid string (same as official SDK)
        $crc_channel = sprintf('%u', crc32($this->channelName) & 0xffffffff);
        $crc_uid     = sprintf('%u', crc32($this->uid) & 0xffffffff);

        // Pack: sig (32 bytes) + crcChannel (4 bytes LE) + crcUid (4 bytes LE) + msgLen (2 bytes LE) + msg
        $content = $sig
            . pack('V', (int)$crc_channel)
            . pack('V', (int)$crc_uid)
            . pack('v', strlen($msg))
            . $msg;

        return '006' . $this->appID . base64_encode($content);
    }
}

class AgoraTokenBuilder {
    const RolePublisher  = 1;
    const RoleSubscriber = 2;
    const RoleAttendee   = 0;
    const RoleAdmin      = 101;

    /**
     * Build an RTC token.
     * @param int $uid  Use 0 to let Agora assign a UID (matches joinChannel uid:0).
     */
    public static function buildTokenWithUid($appID, $appCertificate, $channelName, $uid = 0, $role = 1, $expireSeconds = 86400) {
        $privilegeExpiredTs = time() + $expireSeconds;

        // uid=0 → empty string (Agora convention for "any uid")
        $uidStr = ($uid === 0 || $uid === '0' || $uid === '') ? '' : (string)$uid;

        $token = new AccessToken($appID, $appCertificate, $channelName, $uidStr);
        $token->addPrivilege(AccessToken::kJoinChannel, $privilegeExpiredTs);

        if ($role == self::RolePublisher || $role == self::RoleAttendee || $role == self::RoleAdmin) {
            $token->addPrivilege(AccessToken::kPublishAudioStream, $privilegeExpiredTs);
            $token->addPrivilege(AccessToken::kPublishVideoStream, $privilegeExpiredTs);
            $token->addPrivilege(AccessToken::kPublishDataStream,  $privilegeExpiredTs);
        }

        return $token->build();
    }
}
