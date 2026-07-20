<?php
/**
 * Shared Notification Functions for VVC-Attendance
 */

if (!function_exists('sendAppNotificationToUser')) {
    /**
     * Send in-app notification to a specific user
     */
    function sendAppNotificationToUser($mysqli, $target_eid, $title, $message, $admin_id = 'SYSTEM', $expiry_date = null, $image_url = null) {
        // 1. Insert into notifications table
        $stmt = $mysqli->prepare("INSERT INTO notifications (admin_id, title, message, recipient_type, recipient_info, expiry_date, image_url) VALUES (?, ?, ?, 'specific', ?, ?, ?)");
        if (!$stmt) return false;
        $stmt->bind_param("ssssss", $admin_id, $title, $message, $target_eid, $expiry_date, $image_url);
        if (!$stmt->execute()) return false;
        $nid = $mysqli->insert_id;
        $stmt->close();

        // 2. Map to user
        $stmt2 = $mysqli->prepare("INSERT INTO user_notifications (notification_id, employee_id) VALUES (?, ?)");
        if ($stmt2) {
            $stmt2->bind_param("is", $nid, $target_eid);
            $stmt2->execute();
            $stmt2->close();
        }

        // 3. WebPush integration (requires webpush_functions.php)
        if (function_exists('sendWebPushNotification')) {
            sendWebPushNotification($mysqli, $target_eid, $title, $message, $image_url);
        }

        // 4. FCM integration (Mobile Push Notification)
        if (function_exists('sendFCMNotification')) {
            sendFCMNotification($mysqli, $target_eid, $title, $message, $image_url);
        }

        return true;
    }
}

if (!function_exists('sendFCMNotification')) {
    function sendFCMNotification($mysqli, $target_eid, $title, $message, $image_url = null, $extra_data = []) {
        // If target_eid starts with /topics/, it's a topic, not a user EID
        $is_topic = (strpos($target_eid, '/topics/') === 0);
        $tokens = [];

        if ($is_topic) {
            $tokens[] = $target_eid;
        } else {
            // Priority: Fetch all devices from user_fcm_tokens
            $res = $mysqli->query("SELECT fcm_token FROM user_fcm_tokens WHERE employee_id = '$target_eid'");
            if ($res && $res->num_rows > 0) {
                while ($row = $res->fetch_assoc()) {
                    $tokens[] = $row['fcm_token'];
                }
            } else {
                // Fallback to users table 
                $res_u = $mysqli->query("SELECT fcm_token FROM users WHERE employee_id = '$target_eid' AND fcm_token IS NOT NULL AND fcm_token != ''");
                if ($res_u && $row_u = $res_u->fetch_assoc()) {
                    $tokens[] = $row_u['fcm_token'];
                }
            }
        }

        if (empty($tokens)) return false;
        
        // Configuration
        $service_account_file = __DIR__ . '/firebase-adminsdk.json';
        if (!file_exists($service_account_file)) return false;
        $sa = json_decode(file_get_contents($service_account_file), true);
        if (!$sa) return false;

        // 1. Create JWT (OAuth for FCM v1)
        // ... (truncated helper functions)
        $base64UrlExt = function($data) {
            return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
        };
        $header = json_encode(['alg' => 'RS256', 'typ' => 'JWT']);
        $now = time();
        $claim = json_encode([
            'iss' => $sa['client_email'],
            'sub' => $sa['client_email'],
            'aud' => 'https://oauth2.googleapis.com/token',
            'iat' => $now,
            'exp' => $now + 3600,
            'scope' => 'https://www.googleapis.com/auth/firebase.messaging'
        ]);

        $signatureInput = $base64UrlExt($header) . '.' . $base64UrlExt($claim);
        $signature = '';
        openssl_sign($signatureInput, $signature, $sa['private_key'], OPENSSL_ALGO_SHA256);
        $jwt = $signatureInput . '.' . $base64UrlExt($signature);

        // 2. Get Access Token (reuse logic)
        $ch_auth = curl_init('https://oauth2.googleapis.com/token');
        curl_setopt($ch_auth, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch_auth, CURLOPT_POST, true);
        curl_setopt($ch_auth, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $jwt
        ]));
        curl_setopt($ch_auth, CURLOPT_SSL_VERIFYPEER, false);
        $auth_resp = curl_exec($ch_auth);
        curl_close($ch_auth);
        $token_data = json_decode($auth_resp, true);
        if (!isset($token_data['access_token'])) return false;
        $access_token = $token_data['access_token'];

        // 3. Send Notification to ALL tokens
        $url = 'https://fcm.googleapis.com/v1/projects/' . $sa['project_id'] . '/messages:send';
        $results = [];

        foreach ($tokens as $token) {
            $message_target_key = $is_topic ? 'topic' : 'token';
            $message_target_val = $token;
            if ($is_topic && strpos($message_target_val, '/topics/') === 0) {
                $message_target_val = str_replace('/topics/', '', $message_target_val);
            }

            $notif_payload = [
                'title' => $title,
                'body' => $message
            ];
            if ($image_url) {
                $notif_payload['image'] = $image_url;
            }

            $fcm_payload = [
                'message' => [
                    $message_target_key => $message_target_val,
                    'notification' => $notif_payload,
                    'data' => array_merge([
                        'click_action' => 'FLUTTER_NOTIFICATION_CLICK',
                        'id' => '1',
                        'status' => 'done',
                    ], $extra_data),
                    'android' => [
                        'priority' => ($extra_data['priority'] ?? 'high') == 'high' ? 'high' : 'normal',
                        'notification' => [
                            // Android resource (no extension)
                            'sound' => str_replace('.mp3', '', $extra_data['sound'] ?? 'default'),
                            'channel_id' => $extra_data['channel_id'] ?? 'vvc_hrm_channel',
                            'click_action' => 'FLUTTER_NOTIFICATION_CLICK'
                        ]
                    ],
                    'apns' => [
                        'payload' => [
                            'aps' => [
                                'alert' => [
                                    'title' => $title,
                                    'body' => $message
                                ],
                                // iOS needs extension
                                'sound' => ($extra_data['sound'] ?? 'default') == 'default' ? 'default' : ($extra_data['sound'] . (strpos($extra_data['sound'], '.') === false ? '.mp3' : '')),
                                'badge' => 1,
                                'content-available' => 1,
                                'mutable-content' => 1
                            ]
                        ],
                        'fcm_options' => [
                            'image' => $image_url ?: ''
                        ]
                    ],
                    'webpush' => [
                        'notification' => [
                            'title' => $title,
                            'body' => $message,
                            'icon' => '/icons/Icon-192.png',
                            'image' => $image_url
                        ]
                    ]
                ]
            ];

            // Add image to android if exists
            if ($image_url) {
                $fcm_payload['message']['android']['notification']['image'] = $image_url;
            }

            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Authorization: Bearer ' . $access_token,
                'Content-Type: application/json'
            ]);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($fcm_payload));
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            $result = curl_exec($ch);
            curl_close($ch);
            
            // Cleanup invalid tokens if possible
            if ($result) {
                $res_json = json_decode($result, true);
                if (isset($res_json['error']) && ($res_json['error']['status'] == 'UNREGISTERED' || $res_json['error']['status'] == 'INVALID_ARGUMENT')) {
                    $token_q = $mysqli->real_escape_string($token);
                    $mysqli->query("DELETE FROM user_fcm_tokens WHERE fcm_token = '$token_q'");
                }
            }
            $results[] = $result;
        }

        return json_encode(['tokens_sent' => count($tokens), 'details' => $results]);
    }
}

if (!function_exists('sendAppNotificationToRoles')) {
    /**
     * Send in-app notification to all users matching certain system roles
     */
    function sendAppNotificationToRoles($mysqli, $roles, $title, $message, $admin_id = 'SYSTEM', $expiry_date = null, $image_url = null, $extra_data = []) {
        if (empty($roles)) return false;

        $display_roles = [];
        $match_roles = [];
        foreach ($roles as $role) {
            $role = trim((string)$role);
            if ($role === '') continue;
            $display_roles[] = $role;
            $match_roles[] = strtolower($role);
        }
        $display_roles = array_values(array_unique($display_roles));
        $match_roles = array_values(array_unique($match_roles));
        if (empty($match_roles)) return false;

        // 1. Insert into notifications
        $stmt = $mysqli->prepare("INSERT INTO notifications (admin_id, title, message, recipient_type, recipient_info, expiry_date, image_url) VALUES (?, ?, ?, 'role', ?, ?, ?)");
        if (!$stmt) return false;
        $roles_str = implode(',', $display_roles);
        $stmt->bind_param("ssssss", $admin_id, $title, $message, $roles_str, $expiry_date, $image_url);
        if (!$stmt->execute()) return false;
        $nid = $mysqli->insert_id;
        $stmt->close();

        // 2. Insert for multiple users by role. Match both system_role and user_role
        // so legacy Admin accounts still receive HRM/Admin alerts.
        $placeholders = implode(',', array_fill(0, count($match_roles), '?'));
        $role_where = "(LOWER(TRIM(COALESCE(system_role, ''))) IN ($placeholders)
                       OR LOWER(TRIM(COALESCE(user_role, ''))) IN ($placeholders))";
        $sql = "INSERT INTO user_notifications (notification_id, employee_id)
                SELECT DISTINCT ?, employee_id FROM users
                WHERE $role_where AND COALESCE(employee_id, '') != ''";
        $stmt2 = $mysqli->prepare($sql);
        if ($stmt2) {
            $insert_params = array_merge([$nid], $match_roles, $match_roles);
            $types = "i" . str_repeat("s", count($match_roles) * 2);
            $bind_names = [$types];
            for ($i = 0; $i < count($insert_params); $i++) {
                $bind_names[] = &$insert_params[$i];
            }
            call_user_func_array([$stmt2, 'bind_param'], $bind_names);
            $stmt2->execute();
            $stmt2->close();
        }

        // 3. WebPush for each person in those roles
        if (true) {
            $uSql = "SELECT DISTINCT employee_id FROM users
                     WHERE $role_where AND COALESCE(employee_id, '') != ''";
            $uStmt = $mysqli->prepare($uSql);
            if ($uStmt) {
                $target_params = array_merge($match_roles, $match_roles);
                $uTypes = str_repeat("s", count($match_roles) * 2);
                $uBind_names = [$uTypes];
                for ($i = 0; $i < count($target_params); $i++) {
                    $uBind_names[] = &$target_params[$i];
                }
                call_user_func_array([$uStmt, 'bind_param'], $uBind_names);
                $uStmt->execute();
                $uRes = $uStmt->get_result();
                if ($uRes) {
                    while ($uRow = $uRes->fetch_assoc()) {
                        if (function_exists('sendWebPushNotification')) {
                            sendWebPushNotification($mysqli, $uRow['employee_id'], $title, $message, $image_url);
                        }
                        if (function_exists('sendFCMNotification')) {
                            sendFCMNotification($mysqli, $uRow['employee_id'], $title, $message, $image_url, $extra_data);
                        }
                    }
                }
                $uStmt->close();
            }
        }

        return true;
    }
}

if (!function_exists('sendAppNotificationToAll')) {
    /**
     * Send in-app notification to ALL active users
     */
    function sendAppNotificationToAll($mysqli, $title, $message, $admin_id = 'SYSTEM', $expiry_date = null, $image_url = null, $extra_data = []) {
        // 1. Insert into notifications
        $stmt = $mysqli->prepare("INSERT INTO notifications (admin_id, title, message, recipient_type, expiry_date, image_url) VALUES (?, ?, ?, 'all', ?, ?)");
        if (!$stmt) return false;
        $stmt->bind_param("sssss", $admin_id, $title, $message, $expiry_date, $image_url);
        if (!$stmt->execute()) return false;
        $nid = $mysqli->insert_id;
        $stmt->close();

        // 2. Insert for ALL users
        $sql = "INSERT INTO user_notifications (notification_id, employee_id)
                SELECT ?, employee_id FROM users WHERE employment_status = 'Active'";
        $stmt2 = $mysqli->prepare($sql);
        if ($stmt2) {
            $stmt2->bind_param("i", $nid);
            $stmt2->execute();
            $stmt2->close();
        }

        // 3. Send via FCM Topic or individually
        // Here we send to /topics/all if subscribed, or we could loop.
        // Let's loop for precision as topics might not be set up for everyone.
        $uRes = $mysqli->query("SELECT employee_id FROM users WHERE employment_status = 'Active'");
        if ($uRes) {
            while ($uRow = $uRes->fetch_assoc()) {
                if (function_exists('sendWebPushNotification')) {
                    sendWebPushNotification($mysqli, $uRow['employee_id'], $title, $message, $image_url);
                }
                sendFCMNotification($mysqli, $uRow['employee_id'], $title, $message, $image_url, $extra_data);
            }
        }

        return true;
    }
}
