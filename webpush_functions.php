<?php
require_once __DIR__ . '/vendor/autoload.php';
use Minishlink\WebPush\WebPush;
use Minishlink\WebPush\Subscription;

function sendWebPushNotification($mysqli, $target_employee_id, $title, $body) {
    if (!$target_employee_id) return false;

    // 1. Fetch subscriptions for the target user
    $sql = "SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE employee_id = ?";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("s", $target_employee_id);
        $stmt->execute();
        $res = $stmt->get_result();
        $subscriptions = [];
        while ($row = $res->fetch_assoc()) {
            $subscriptions[] = Subscription::create([
                'endpoint' => $row['endpoint'],
                'keys' => [
                    'p256dh' => $row['p256dh'],
                    'auth' => $row['auth']
                ]
            ]);
        }
        $stmt->close();

        if (empty($subscriptions)) {
            error_log("[WebPush] No subscriptions found for employee: " . $target_employee_id);
            return false;
        }
        error_log("[WebPush] Found " . count($subscriptions) . " subscriptions for employee: " . $target_employee_id);

        // 2. Setup WebPush
        $auth = [
            'VAPID' => [
                'subject' => 'mailto:admin@vvc-attendance.com',
                'publicKey' => VAPID_PUBLIC_KEY,
                'privateKey' => VAPID_PRIVATE_KEY,
            ],
        ];

        try {
            $webPush = new WebPush($auth);

            $payload = json_encode([
                'title' => $title,
                'body' => $body
            ]);

            foreach ($subscriptions as $subscription) {
                $webPush->queueNotification($subscription, $payload);
            }

            foreach ($webPush->flush() as $report) {
                $endpoint = $report->getEndpoint();
                if (!$report->isSuccess()) {
                    error_log("[WebPush] Message failed for {$endpoint} : {$report->getReason()}");
                    if ($report->isSubscriptionExpired()) {
                         $mysqli->query("DELETE FROM push_subscriptions WHERE endpoint = '" . $mysqli->real_escape_string($endpoint) . "'");
                    }
                }
            }
            return true;
        } catch (Exception $e) {
            error_log("[WebPush] Error: " . $e->getMessage());
            return false;
        }
    }
    return false;
}
?>
