<?php
/**
 * Official Agora RTC Token Builder (v006 Pure PHP)
 * Generates standards-compliant Dynamic RTC Tokens for Voice & Video calls
 */

class Message {
    public $salt;
    public $ts;
    public $privileges;

    public function __construct() {
        $this->salt = rand(1, 99999999);
        $this->ts = time() + 24 * 3600;
        $this->privileges = array();
    }

    public function packContent() {
        $buffer = pack("V", $this->salt);
        $buffer .= pack("V", $this->ts);
        $buffer .= pack("v", count($this->privileges));
        foreach ($this->privileges as $key => $value) {
            $buffer .= pack("v", $key);
            $buffer .= pack("V", $value);
        }
        return $buffer;
    }
}

class AccessToken {
    const Privileges = array(
        "kJoinChannel" => 1,
        "kPublishAudioStream" => 2,
        "kPublishVideoStream" => 3,
        "kPublishDataStream" => 4,
    );

    public $appID;
    public $appCertificate;
    public $channelName;
    public $uid;
    public $message;

    public function __construct($appID, $appCertificate, $channelName, $uid) {
        $this->appID = $appID;
        $this->appCertificate = $appCertificate;
        $this->channelName = $channelName;
        $this->uid = (string)$uid;
        $this->message = new Message();
    }

    public function addPrivilege($key, $expireTimestamp) {
        $this->message->privileges[$key] = $expireTimestamp;
        return $this;
    }

    public function build() {
        $msg = $this->message->packContent();
        $val = $this->appID . $this->channelName . $this->uid . $msg;

        $sig = hash_hmac('sha256', $val, $this->appCertificate, true);

        $crc_channel = crc32($this->channelName) & 0xffffffff;
        $crc_uid = crc32($this->uid) & 0xffffffff;

        $content = $sig . pack("V", $crc_channel) . pack("V", $crc_uid) . pack("v", strlen($msg)) . $msg;

        $version = "006";
        return $version . $this->appID . base64_encode($content);
    }
}

class AgoraTokenBuilder {
    const RoleAttendee = 0;
    const RolePublisher = 1;
    const RoleSubscriber = 2;
    const RoleAdmin = 101;

    public static function buildTokenWithUid($appID, $appCertificate, $channelName, $uid = 0, $role = 1, $expireTimestamp = 86400) {
        return self::buildTokenWithUserAccount($appID, $appCertificate, $channelName, (string)$uid, $role, $expireTimestamp);
    }

    public static function buildTokenWithUserAccount($appID, $appCertificate, $channelName, $account = "", $role = 1, $expireTimestamp = 86400) {
        $privilegeExpiredTs = time() + $expireTimestamp;
        $token = new AccessToken($appID, $appCertificate, $channelName, $account);
        $token->addPrivilege(AccessToken::Privileges["kJoinChannel"], $privilegeExpiredTs);
        if ($role == self::RolePublisher || $role == self::RoleAttendee || $role == self::RoleAdmin) {
            $token->addPrivilege(AccessToken::Privileges["kPublishAudioStream"], $privilegeExpiredTs);
            $token->addPrivilege(AccessToken::Privileges["kPublishVideoStream"], $privilegeExpiredTs);
            $token->addPrivilege(AccessToken::Privileges["kPublishDataStream"], $privilegeExpiredTs);
        }
        return $token->build();
    }
}
