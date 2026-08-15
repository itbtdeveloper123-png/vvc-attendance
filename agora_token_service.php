<?php
/**
 * Agora RTC Token Builder (v006 Pure PHP)
 * Used to generate dynamic RTC Tokens for Voice & Video calls
 */

class AgoraTokenBuilder {
    const RolePublisher = 1;
    const RoleSubscriber = 2;

    public static function buildTokenWithUid($appId, $appCertificate, $channelName, $uid = 0, $role = 1, $expireTimeInSeconds = 86400) {
        $account = ($uid === 0 || $uid === "0" || empty($uid)) ? "" : (string)$uid;
        return self::buildTokenWithAccount($appId, $appCertificate, $channelName, $account, $role, $expireTimeInSeconds);
    }

    public static function buildTokenWithAccount($appId, $appCertificate, $channelName, $account = "", $role = 1, $expireTimeInSeconds = 86400) {
        $currentTimestamp = time();
        $privilegeExpiredTs = $currentTimestamp + $expireTimeInSeconds;

        $salt = rand(1, 99999999);

        // Privilege map
        // 1: kJoinChannel, 2: kPublishAudioStream, 3: kPublishVideoStream, 4: kPublishDataStream
        $privileges = [
            1 => $privilegeExpiredTs,
            2 => $privilegeExpiredTs,
            3 => $privilegeExpiredTs,
            4 => $privilegeExpiredTs,
        ];

        // Pack message
        $msg = pack("a*", $appId) . pack("a*", $channelName) . pack("a*", (string)$account) . pack("V", $salt) . pack("v", count($privileges));
        foreach ($privileges as $key => $value) {
            $msg .= pack("v", $key) . pack("V", $value);
        }

        $appCertBin = hex2bin($appCertificate);
        $signature = hash_hmac("sha256", $msg, $appCertBin, true);

        $crcChannel = sprintf("%u", crc32($channelName) & 0xffffffff);
        $crcAccount = sprintf("%u", crc32((string)$account) & 0xffffffff);

        $content = pack("a*", $signature) . pack("a*", $crcChannel) . pack("a*", $crcAccount) . pack("a*", $msg);
        return "006" . $appId . base64_encode($content);
    }
}
