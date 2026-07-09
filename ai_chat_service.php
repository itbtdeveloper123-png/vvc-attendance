<?php

require_once __DIR__ . '/ai_tools.php';
require_once __DIR__ . '/ai_provider_openai.php';

if (!function_exists('ai_chat_fix_mojibake_text')) {
    function ai_chat_fix_mojibake_text($text)
    {
        $text = (string)$text;
        if ($text === '') {
            return $text;
        }

        if (strpos($text, 'á') === false && strpos($text, 'ž') === false && strpos($text, 'Ÿ') === false) {
            return $text;
        }

        $win1252Map = [
            0x20AC => 0x80,
            0x201A => 0x82,
            0x0192 => 0x83,
            0x201E => 0x84,
            0x2026 => 0x85,
            0x2020 => 0x86,
            0x2021 => 0x87,
            0x02C6 => 0x88,
            0x2030 => 0x89,
            0x0160 => 0x8A,
            0x2039 => 0x8B,
            0x0152 => 0x8C,
            0x017D => 0x8E,
            0x2018 => 0x91,
            0x2019 => 0x92,
            0x201C => 0x93,
            0x201D => 0x94,
            0x2022 => 0x95,
            0x2013 => 0x96,
            0x2014 => 0x97,
            0x02DC => 0x98,
            0x2122 => 0x99,
            0x0161 => 0x9A,
            0x203A => 0x9B,
            0x0153 => 0x9C,
            0x017E => 0x9E,
            0x0178 => 0x9F,
        ];

        $chars = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
        if (!is_array($chars)) {
            return $text;
        }

        $bytes = '';
        foreach ($chars as $char) {
            if (!function_exists('mb_ord')) {
                return $text;
            }

            $code = mb_ord($char, 'UTF-8');
            if ($code >= 0x00 && $code <= 0xFF) {
                $bytes .= chr($code);
                continue;
            }
            if (isset($win1252Map[$code])) {
                $bytes .= chr($win1252Map[$code]);
                continue;
            }

            return $text;
        }

        $fixed = @iconv('Windows-1252', 'UTF-8//IGNORE', $bytes);
        if (!is_string($fixed) || $fixed === '') {
            return $text;
        }

        return preg_match('/[\x{1780}-\x{17FF}]/u', $fixed) ? $fixed : $text;
    }
}

if (!function_exists('ensure_ai_chat_tables')) {
    function ensure_ai_chat_tables(mysqli $mysqli)
    {
        $mysqli->query("CREATE TABLE IF NOT EXISTS ai_chat_sessions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_id VARCHAR(64) NOT NULL,
            title VARCHAR(255) DEFAULT NULL,
            provider VARCHAR(50) DEFAULT 'local',
            model_name VARCHAR(100) DEFAULT NULL,
            conversation_id VARCHAR(191) DEFAULT NULL,
            previous_response_id VARCHAR(191) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_employee (employee_id),
            KEY idx_updated (updated_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        $mysqli->query("CREATE TABLE IF NOT EXISTS ai_chat_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            session_id INT NOT NULL,
            employee_id VARCHAR(64) NOT NULL,
            sender_type ENUM('user', 'assistant', 'tool', 'system') NOT NULL,
            message_text LONGTEXT DEFAULT NULL,
            tool_name VARCHAR(100) DEFAULT NULL,
            tool_payload_json LONGTEXT DEFAULT NULL,
            tool_result_json LONGTEXT DEFAULT NULL,
            model_name VARCHAR(100) DEFAULT NULL,
            attachment_type VARCHAR(50) DEFAULT NULL,
            attachment_path VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_session (session_id),
            KEY idx_employee (employee_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        $messageCols = [];
        $colsRes = $mysqli->query("SHOW COLUMNS FROM ai_chat_messages");
        if ($colsRes) {
            while ($col = $colsRes->fetch_assoc()) {
                $messageCols[$col['Field']] = true;
            }
        }
        if (!isset($messageCols['attachment_type'])) {
            $mysqli->query("ALTER TABLE ai_chat_messages ADD COLUMN attachment_type VARCHAR(50) DEFAULT NULL AFTER model_name");
        }
        if (!isset($messageCols['attachment_path'])) {
            $mysqli->query("ALTER TABLE ai_chat_messages ADD COLUMN attachment_path VARCHAR(255) DEFAULT NULL AFTER attachment_type");
        }
    }
}

if (!function_exists('ai_chat_default_session_title')) {
    function ai_chat_default_session_title($message = '')
    {
        $message = trim(ai_chat_fix_mojibake_text((string)$message));
        if ($message === '') {
            return 'AI Assistant';
        }
        $title = mb_substr($message, 0, 50, 'UTF-8');
        return $title !== '' ? $title : 'AI Assistant';
    }
}

if (!function_exists('ai_chat_create_session')) {
    function ai_chat_create_session(mysqli $mysqli, $employeeId, $title = '')
    {
        $config = ai_chat_resolve_provider_config();
        $provider = $config['provider'] ?? 'local';
        $model = $config['model'] ?? 'local-fallback';
        $title = trim((string)$title);
        if ($title === '') {
            $title = 'AI Assistant';
        }

        $stmt = $mysqli->prepare("INSERT INTO ai_chat_sessions (employee_id, title, provider, model_name) VALUES (?, ?, ?, ?)");
        if (!$stmt) {
            return ['success' => false, 'message' => 'Prepare failed'];
        }
        $stmt->bind_param('ssss', $employeeId, $title, $provider, $model);
        $ok = $stmt->execute();
        $sessionId = (int)$mysqli->insert_id;
        $stmt->close();

        if (!$ok) {
            return ['success' => false, 'message' => 'Failed to create AI chat session'];
        }

        return [
            'success' => true,
            'session' => [
                'id' => $sessionId,
                'employee_id' => $employeeId,
                'title' => $title,
                'provider' => $provider,
                'model_name' => $model,
            ],
        ];
    }
}

if (!function_exists('ai_chat_get_sessions')) {
    function ai_chat_get_sessions(mysqli $mysqli, $employeeId, $limit = 20)
    {
        $limit = max(1, min(50, (int)$limit));
        $stmt = $mysqli->prepare("SELECT id, title, provider, model_name,
                                         DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at,
                                         DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s') AS updated_at
                                  FROM ai_chat_sessions
                                  WHERE employee_id = ?
                                  ORDER BY updated_at DESC
                                  LIMIT ?");
        if (!$stmt) {
            return [];
        }
        $stmt->bind_param('si', $employeeId, $limit);
        $stmt->execute();
        $res = $stmt->get_result();
        $sessions = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $row['title'] = ai_chat_fix_mojibake_text((string)($row['title'] ?? ''));
                $sessions[] = $row;
            }
        }
        $stmt->close();
        return $sessions;
    }
}

if (!function_exists('ai_chat_get_history')) {
    function ai_chat_get_history(mysqli $mysqli, $employeeId, $sessionId, $limit = 100)
    {
        $limit = max(1, min(200, (int)$limit));
        $stmt = $mysqli->prepare("SELECT m.id, m.sender_type, m.message_text, m.tool_name, m.model_name,
                                         m.attachment_type, m.attachment_path,
                                         DATE_FORMAT(m.created_at, '%Y-%m-%d %H:%i:%s') AS created_at
                                  FROM ai_chat_messages m
                                  JOIN ai_chat_sessions s ON s.id = m.session_id
                                  WHERE m.session_id = ?
                                    AND s.employee_id = ?
                                    AND m.sender_type IN ('user', 'assistant')
                                  ORDER BY m.id DESC
                                  LIMIT ?");
        if (!$stmt) {
            return [];
        }
        $stmt->bind_param('isi', $sessionId, $employeeId, $limit);
        $stmt->execute();
        $res = $stmt->get_result();
        $items = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $row['message_text'] = ai_chat_fix_mojibake_text((string)($row['message_text'] ?? ''));
                $items[] = $row;
            }
        }
        $stmt->close();
        return array_reverse($items);
    }
}

if (!function_exists('ai_chat_insert_message')) {
    function ai_chat_insert_message(
        mysqli $mysqli,
        $sessionId,
        $employeeId,
        $senderType,
        $messageText = null,
        $toolName = null,
        $toolPayloadJson = null,
        $toolResultJson = null,
        $modelName = null,
        $attachmentType = null,
        $attachmentPath = null
    ) {
        $stmt = $mysqli->prepare("INSERT INTO ai_chat_messages (
            session_id, employee_id, sender_type, message_text, tool_name,
            tool_payload_json, tool_result_json, model_name, attachment_type, attachment_path
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        if (!$stmt) {
            return 0;
        }
        $stmt->bind_param(
            'isssssssss',
            $sessionId,
            $employeeId,
            $senderType,
            $messageText,
            $toolName,
            $toolPayloadJson,
            $toolResultJson,
            $modelName,
            $attachmentType,
            $attachmentPath
        );
        if (!$stmt->execute()) {
            $stmt->close();
            return 0;
        }
        $messageId = (int)$mysqli->insert_id;
        $stmt->close();
        return $messageId;
    }
}

if (!function_exists('ai_chat_touch_session')) {
    function ai_chat_touch_session(mysqli $mysqli, $sessionId, $title = null, $provider = null, $modelName = null)
    {
        $fields = ["updated_at = NOW()"];
        $types = '';
        $params = [];

        if ($title !== null && trim((string)$title) !== '') {
            $fields[] = "title = ?";
            $types .= 's';
            $params[] = $title;
        }
        if ($provider !== null && trim((string)$provider) !== '') {
            $fields[] = "provider = ?";
            $types .= 's';
            $params[] = $provider;
        }
        if ($modelName !== null && trim((string)$modelName) !== '') {
            $fields[] = "model_name = ?";
            $types .= 's';
            $params[] = $modelName;
        }

        $sql = "UPDATE ai_chat_sessions SET " . implode(', ', $fields) . " WHERE id = ?";
        $types .= 'i';
        $params[] = (int)$sessionId;

        $stmt = $mysqli->prepare($sql);
        if (!$stmt) {
            return;
        }
        $bindValues = [];
        $bindValues[] = $types;
        foreach ($params as $key => $value) {
            $bindValues[] = &$params[$key];
        }
        call_user_func_array([$stmt, 'bind_param'], $bindValues);
        $stmt->execute();
        $stmt->close();
    }
}

if (!function_exists('ai_chat_validate_session_owner')) {
    function ai_chat_validate_session_owner(mysqli $mysqli, $sessionId, $employeeId)
    {
        $stmt = $mysqli->prepare("SELECT id, title FROM ai_chat_sessions WHERE id = ? AND employee_id = ? LIMIT 1");
        if (!$stmt) {
            return null;
        }
        $stmt->bind_param('is', $sessionId, $employeeId);
        $stmt->execute();
        $res = $stmt->get_result();
        $row = $res ? $res->fetch_assoc() : null;
        $stmt->close();
        if ($row) {
            $row['title'] = ai_chat_fix_mojibake_text((string)($row['title'] ?? ''));
        }
        return $row;
    }
}

if (!function_exists('ai_chat_delete_session')) {
    function ai_chat_delete_session(mysqli $mysqli, $sessionId, $employeeId)
    {
        $sessionId = (int)$sessionId;
        $employeeId = trim((string)$employeeId);
        if ($sessionId <= 0 || $employeeId === '') {
            return ['success' => false, 'message' => 'Invalid session or employee'];
        }

        $session = ai_chat_validate_session_owner($mysqli, $sessionId, $employeeId);
        if (!$session) {
            return ['success' => false, 'message' => 'Chat session not found'];
        }

        try {
            $mysqli->begin_transaction();

            $deleteMessagesStmt = $mysqli->prepare("DELETE FROM ai_chat_messages WHERE session_id = ?");
            if (!$deleteMessagesStmt) {
                throw new RuntimeException('Prepare failed for chat messages delete');
            }
            $deleteMessagesStmt->bind_param('i', $sessionId);
            if (!$deleteMessagesStmt->execute()) {
                $deleteMessagesStmt->close();
                throw new RuntimeException('Failed to delete chat messages');
            }
            $deleteMessagesStmt->close();

            $deleteSessionStmt = $mysqli->prepare("DELETE FROM ai_chat_sessions WHERE id = ? AND employee_id = ? LIMIT 1");
            if (!$deleteSessionStmt) {
                throw new RuntimeException('Prepare failed for chat session delete');
            }
            $deleteSessionStmt->bind_param('is', $sessionId, $employeeId);
            if (!$deleteSessionStmt->execute()) {
                $deleteSessionStmt->close();
                throw new RuntimeException('Failed to delete chat session');
            }
            $affected = (int)$deleteSessionStmt->affected_rows;
            $deleteSessionStmt->close();

            if ($affected <= 0) {
                throw new RuntimeException('Chat session was not deleted');
            }

            $mysqli->commit();

            return [
                'success' => true,
                'message' => 'Chat history deleted successfully',
                'deleted_session_id' => $sessionId,
                'deleted_title' => (string)($session['title'] ?? 'AI Assistant'),
            ];
        } catch (Throwable $e) {
            $mysqli->rollback();
            return [
                'success' => false,
                'message' => 'Failed to delete chat history',
            ];
        }
    }
}

if (!function_exists('ai_chat_delete_all_sessions')) {
    function ai_chat_delete_all_sessions(mysqli $mysqli, $employeeId)
    {
        $employeeId = trim((string)$employeeId);
        if ($employeeId === '') {
            return ['success' => false, 'message' => 'Invalid employee'];
        }

        $countStmt = $mysqli->prepare("SELECT COUNT(*) FROM ai_chat_sessions WHERE employee_id = ?");
        if (!$countStmt) {
            return ['success' => false, 'message' => 'Failed to prepare session count'];
        }
        $countStmt->bind_param('s', $employeeId);
        $countStmt->execute();
        $countRes = $countStmt->get_result();
        $sessionCount = $countRes ? (int)($countRes->fetch_row()[0] ?? 0) : 0;
        $countStmt->close();

        if ($sessionCount <= 0) {
            return [
                'success' => true,
                'message' => 'No chat history to delete',
                'deleted_sessions_count' => 0,
            ];
        }

        try {
            $mysqli->begin_transaction();

            $deleteMessagesStmt = $mysqli->prepare(
                "DELETE m
                 FROM ai_chat_messages m
                 INNER JOIN ai_chat_sessions s ON s.id = m.session_id
                 WHERE s.employee_id = ?"
            );
            if (!$deleteMessagesStmt) {
                throw new RuntimeException('Prepare failed for bulk chat messages delete');
            }
            $deleteMessagesStmt->bind_param('s', $employeeId);
            if (!$deleteMessagesStmt->execute()) {
                $deleteMessagesStmt->close();
                throw new RuntimeException('Failed to delete chat messages');
            }
            $deleteMessagesStmt->close();

            $deleteSessionsStmt = $mysqli->prepare("DELETE FROM ai_chat_sessions WHERE employee_id = ?");
            if (!$deleteSessionsStmt) {
                throw new RuntimeException('Prepare failed for bulk chat sessions delete');
            }
            $deleteSessionsStmt->bind_param('s', $employeeId);
            if (!$deleteSessionsStmt->execute()) {
                $deleteSessionsStmt->close();
                throw new RuntimeException('Failed to delete chat sessions');
            }
            $deletedSessions = (int)$deleteSessionsStmt->affected_rows;
            $deleteSessionsStmt->close();

            $mysqli->commit();

            return [
                'success' => true,
                'message' => 'All chat history deleted successfully',
                'deleted_sessions_count' => $deletedSessions,
            ];
        } catch (Throwable $e) {
            $mysqli->rollback();
            return [
                'success' => false,
                'message' => 'Failed to delete all chat history',
            ];
        }
    }
}

if (!function_exists('ai_chat_build_system_prompt')) {
    function ai_chat_build_system_prompt(array $user)
    {
        $role = (string)($user['system_role'] ?? $user['user_role'] ?? 'Employee');
        $isAdmin = ai_chat_is_admin_like($user);

        $lines = [
            'You are the VVC HRM AI assistant.',
            'Reply in Khmer by default unless the user asks for English.',
            'Use natural, polite Khmer that feels conversational, not robotic.',
            'Prefer short clear paragraphs over stiff bullet lists unless the user asks for a list.',
            'Answer general knowledge questions, casual conversation, explanations, and brainstorming normally when they do not require private HRM data.',
            'Use only tool results for factual claims about attendance, leave, requests, profiles, or team summaries from the HRM system.',
            'If a question depends on HRM data and the needed data is missing, clearly say what data was not found instead of saying the whole feature is unsupported.',
            'If the user asks what you can do, explain that you can answer general questions and also check HRM data such as attendance, leave, requests, and team summaries according to permissions.',
            'Never reveal passwords, tokens, secrets, hidden system settings, or SQL.',
            'Keep answers concise, practical, and easy for staff to understand.',
            'If data is missing, clearly say what was not found.',
            'Current user system role: ' . $role . '.',
        ];

        if ($isAdmin) {
            $lines[] = 'This user is Admin/HRM and may receive team pending request summaries.';
        } else {
            $lines[] = 'This user may only access their own attendance, leave, and requests.';
        }

        return implode("\n", $lines);
    }
}

if (!function_exists('ai_chat_build_model_messages')) {
    function ai_chat_build_model_messages(mysqli $mysqli, array $user, $sessionId, $latestUserMessage, $excludeLatestAssistant = false)
    {
        $history = ai_chat_get_history($mysqli, (string)$user['employee_id'], (int)$sessionId, 20);
        if ($excludeLatestAssistant && !empty($history)) {
            $lastIndex = count($history) - 1;
            if (($history[$lastIndex]['sender_type'] ?? '') === 'assistant') {
                array_pop($history);
            }
        }
        $messages = [
            [
                'role' => 'system',
                'content' => ai_chat_build_system_prompt($user),
            ],
        ];

        foreach ($history as $item) {
            $sender = $item['sender_type'] === 'assistant' ? 'assistant' : 'user';
            $text = trim((string)($item['message_text'] ?? ''));
            if ($text === '') {
                continue;
            }
            $messages[] = [
                'role' => $sender,
                'content' => $text,
            ];
        }

        $latestUserMessage = trim((string)$latestUserMessage);
        if ($latestUserMessage !== '') {
            $messages[] = [
                'role' => 'user',
                'content' => $latestUserMessage,
            ];
        }

        return $messages;
    }
}

if (!function_exists('ai_chat_collect_sources')) {
    function ai_chat_collect_sources(array $trace)
    {
        $sources = [];
        foreach ($trace as $toolItem) {
            $toolName = trim((string)($toolItem['tool'] ?? ''));
            if ($toolName !== '' && !in_array($toolName, $sources, true)) {
                $sources[] = $toolName;
            }
        }
        return $sources;
    }
}

if (!function_exists('ai_chat_prepare_reply_payload')) {
    function ai_chat_prepare_reply_payload(mysqli $mysqli, array $user, array $messages, $message)
    {
        $tools = ai_chat_get_tool_definitions($user);
        $providerResult = ai_chat_run_provider_loop(
            $messages,
            $tools,
            function ($toolName, $args) use ($mysqli, $user) {
                return ai_chat_execute_tool($mysqli, $user, $toolName, is_array($args) ? $args : []);
            }
        );

        if (!($providerResult['success'] ?? false) || trim((string)($providerResult['reply'] ?? '')) === '') {
            $providerFailure = $providerResult;
            $fallbackResult = ai_chat_local_fallback($mysqli, $user, $message);
            $fallbackHandled = (bool)($fallbackResult['handled'] ?? false);
            $fallbackReply = trim((string)($fallbackResult['reply'] ?? ''));

            if ($fallbackHandled && $fallbackReply !== '') {
                $providerResult = $fallbackResult;
            } else {
                $providerResult = [
                    'success' => true,
                    'reply' => ai_chat_provider_error_reply($providerFailure),
                    'tool_trace' => [],
                    'provider' => (string)($providerFailure['provider'] ?? 'local'),
                    'model' => (string)($providerFailure['model'] ?? 'local-fallback'),
                ];
            }
        }

        $provider = (string)($providerResult['provider'] ?? 'local');
        $model = (string)($providerResult['model'] ?? 'local-fallback');
        $trace = is_array($providerResult['tool_trace'] ?? null) ? $providerResult['tool_trace'] : [];
        $reply = trim((string)($providerResult['reply'] ?? ''));
        $reply = ai_chat_fix_mojibake_text($reply);
        if ($reply === '') {
            $reply = 'ខ្ញុំមិនអាចបង្កើតចម្លើយបានទេ។ សូមព្យាយាមម្តងទៀត។';
        }

        return [
            'success' => true,
            'reply' => $reply,
            'tool_trace' => $trace,
            'provider' => $provider,
            'model' => $model,
            'sources' => ai_chat_collect_sources($trace),
        ];
    }
}

if (!function_exists('ai_chat_store_reply_payload')) {
    function ai_chat_store_reply_payload(mysqli $mysqli, $sessionId, $employeeId, array $payload)
    {
        $provider = (string)($payload['provider'] ?? 'local');
        $model = (string)($payload['model'] ?? 'local-fallback');
        $trace = is_array($payload['tool_trace'] ?? null) ? $payload['tool_trace'] : [];

        foreach ($trace as $toolItem) {
            ai_chat_insert_message(
                $mysqli,
                $sessionId,
                $employeeId,
                'tool',
                null,
                (string)($toolItem['tool'] ?? ''),
                json_encode($toolItem['arguments'] ?? [], JSON_UNESCAPED_UNICODE),
                json_encode($toolItem['result'] ?? [], JSON_UNESCAPED_UNICODE),
                $model
            );
        }

        $assistantMessageId = ai_chat_insert_message(
            $mysqli,
            $sessionId,
            $employeeId,
            'assistant',
            (string)($payload['reply'] ?? ''),
            null,
            null,
            null,
            $model
        );

        ai_chat_touch_session($mysqli, $sessionId, null, $provider, $model);

        return [
            'success' => true,
            'message_id' => $assistantMessageId,
            'reply' => (string)($payload['reply'] ?? ''),
            'sources' => isset($payload['sources']) && is_array($payload['sources'])
                ? array_values($payload['sources'])
                : ai_chat_collect_sources($trace),
            'tool_trace' => $trace,
            'provider' => $provider,
            'model' => $model,
        ];
    }
}

if (!function_exists('ai_chat_contains_any')) {
    function ai_chat_contains_any($haystack, array $needles)
    {
        $haystack = mb_strtolower((string)$haystack, 'UTF-8');
        foreach ($needles as $needle) {
            if (mb_strpos($haystack, mb_strtolower((string)$needle, 'UTF-8'), 0, 'UTF-8') !== false) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('ai_chat_format_local_reply')) {
    function ai_chat_format_local_reply($toolName, array $result)
    {
        if (!($result['ok'] ?? false)) {
            return 'ខ្ញុំមិនអាចទាញទិន្នន័យនេះបានទេ។ សូមព្យាយាមម្តងទៀត។';
        }

        switch ($toolName) {
            case 'get_my_attendance_today':
                if ((int)($result['total_scans'] ?? 0) <= 0) {
                    return 'ថ្ងៃនេះអ្នកមិនទាន់មានប្រវត្តិ Scan នៅឡើយទេ។';
                }
                $first = $result['first_check_in']['log_time'] ?? null;
                $latest = $result['latest_scan']['log_time'] ?? null;
                $latestAction = $result['latest_scan']['action_type'] ?? '';
                $latestStatus = $result['latest_scan']['status'] ?? '';
                $location = $result['latest_scan']['location_name'] ?? '';

                $parts = [];
                if ($first) {
                    $parts[] = 'ថ្ងៃនេះអ្នកបាន Check-In ដំបូងនៅម៉ោង ' . $first;
                }
                if ($latest) {
                    $parts[] = 'សកម្មភាពចុងក្រោយគឺ ' . $latestAction . ' នៅម៉ោង ' . $latest;
                }
                if ($latestStatus !== '') {
                    $parts[] = 'ស្ថានភាពគឺ ' . $latestStatus;
                }
                if ($location !== '') {
                    $parts[] = 'ទីតាំង ' . $location;
                }
                return implode('។ ', $parts) . '។';

            case 'get_my_leave_balance':
                $balance = number_format((float)($result['annual_leave_balance'] ?? 0), 2);
                $name = $result['profile']['name'] ?? 'អ្នក';
                return $name . ' នៅសល់ច្បាប់ឈប់ប្រចាំឆ្នាំ ' . $balance . ' ថ្ងៃ។';

            case 'get_my_requests':
                $pending = (int)($result['pending_count'] ?? 0);
                $items = $result['items'] ?? [];
                if (empty($items)) {
                    return $pending > 0
                        ? 'អ្នកមានសំណើ Pending ចំនួន ' . $pending . ' ប៉ុន្តែមិនមានបញ្ជីលម្អិតត្រឡប់មកវិញទេ។'
                        : 'ខ្ញុំរកមិនឃើញសំណើរបស់អ្នកនៅឡើយទេ។';
                }
                $first = $items[0];
                return 'អ្នកមានសំណើ Pending ចំនួន ' . $pending . '។ សំណើថ្មីបំផុតគឺ ' .
                    ($first['request_type'] ?? 'មិនមាន') . ' ស្ថានភាព ' . ($first['status'] ?? 'មិនមាន') .
                    ' ថ្ងៃទី ' . ($first['request_date'] ?? 'មិនមាន') . '។';

            case 'get_team_pending_requests':
                $pending = (int)($result['pending_count'] ?? 0);
                return 'បច្ចុប្បន្នមានសំណើ Pending សរុប ' . $pending . '។';
        }

        return 'ខ្ញុំបានទាញទិន្នន័យរួចហើយ ប៉ុន្តែមិនទាន់អាចបកស្រាយសំណួរនេះបានពេញលេញទេ។';
    }
}

if (!function_exists('ai_chat_local_fallback')) {
    function ai_chat_local_fallback(mysqli $mysqli, array $user, $message)
    {
        $message = trim((string)$message);
        $toolName = null;
        $args = [];

        if (ai_chat_contains_any($message, [
            'hello',
            'hi',
            'hey',
            'what can you do',
            'can you help',
            'សួស្តី',
            'ជំរាបសួរ',
            'អាចជួយអ្វីបានខ្លះ',
            'ជួយអ្វីបានខ្លះ',
            'អាចសួរអ្វីបានខ្លះ',
        ])) {
            return [
                'success' => true,
                'handled' => true,
                'reply' => 'បាទ អ្នកអាចសួរសំណួរទូទៅបាន។ បើសួរអំពី attendance, leave, requests ឬទិន្នន័យ HRM ខ្ញុំនឹងប្រើទិន្នន័យតាមសិទ្ធិរបស់អ្នក។',
                'tool_trace' => [],
                'provider' => 'local',
                'model' => 'local-fallback',
            ];
        }

        if (ai_chat_is_admin_like($user) && ai_chat_contains_any($message, [
            'pending all',
            'all pending',
            'team pending',
            'pending requests',
            'សំណើរង់ចាំទាំងអស់',
            'សំណើ pending ទាំងអស់',
            'សំណើក្រុម',
        ])) {
            $toolName = 'get_team_pending_requests';
        } elseif (ai_chat_contains_any($message, [
            'leave',
            'balance',
            'remaining leave',
            'annual leave',
            'ច្បាប់',
            'សល់ច្បាប់',
            'leave balance',
            'ថ្ងៃសល់',
        ])) {
            $toolName = 'get_my_leave_balance';
        } elseif (ai_chat_contains_any($message, [
            'request',
            'requests',
            'pending',
            'approved',
            'rejected',
            'សំណើ',
            'សំណើរបស់ខ្ញុំ',
        ])) {
            $toolName = 'get_my_requests';
        } elseif (ai_chat_contains_any($message, [
            'attendance',
            'check in',
            'check-in',
            'check out',
            'check-out',
            'scan',
            'today',
            'ម៉ោងចូល',
            'ម៉ោងចេញ',
            'វត្តមាន',
            'ស្កេន',
            'ថ្ងៃនេះ',
        ])) {
            $toolName = 'get_my_attendance_today';
        }

        if ($toolName === null) {
            return [
                'success' => true,
                'handled' => false,
                'reply' => 'V1 chatbot ឥឡូវនេះអាចជួយបានជាចម្បងលើ Attendance, Leave balance និង Requests ប៉ុណ្ណោះ។ សូមសួរជាមួយប្រធានបទទាំងនេះសិន។',
                'tool_trace' => [],
                'provider' => 'local',
                'model' => 'local-fallback',
            ];
        }

        $toolResult = ai_chat_execute_tool($mysqli, $user, $toolName, $args);
        return [
            'success' => true,
            'handled' => true,
            'reply' => ai_chat_format_local_reply($toolName, $toolResult),
            'tool_trace' => [
                [
                    'tool' => $toolName,
                    'arguments' => $args,
                    'result' => $toolResult,
                    'ok' => (bool)($toolResult['ok'] ?? false),
                ],
            ],
            'provider' => 'local',
            'model' => 'local-fallback',
        ];
    }
}

if (!function_exists('ai_chat_provider_error_reply')) {
    function ai_chat_provider_error_reply(array $providerResult)
    {
        $raw = trim((string)($providerResult['message'] ?? ''));
        $lower = strtolower($raw);

        if ($raw === '') {
            return 'AI service មិនអាចប្រើបាននៅពេលនេះទេ។ សូមសាកម្តងទៀតបន្តិចក្រោយ។';
        }

        if (strpos($lower, 'quota') !== false || strpos($lower, 'billing') !== false) {
            return 'AI service មិនទាន់អាចប្រើបានទេ ព្រោះ OpenAI quota ឬ billing មានបញ្ហា។ សូមពិនិត្យ balance, plan ឬ billing របស់ API key នេះសិន។';
        }

        if (strpos($lower, 'invalid api key') !== false || strpos($lower, 'incorrect api key') !== false || strpos($lower, 'unauthorized') !== false) {
            return 'AI service មិនទាន់អាចប្រើបានទេ ព្រោះ API key មិនត្រឹមត្រូវ ឬមិនមានសិទ្ធិប្រើ។';
        }

        if (strpos($lower, 'rate limit') !== false) {
            return 'AI service កំពុងជាប់ rate limit។ សូមសាកម្តងទៀតបន្តិចក្រោយ។';
        }

        return 'AI service មិនអាចប្រើបាននៅពេលនេះទេ។ សូមសាកម្តងទៀតបន្តិចក្រោយ។';
    }
}

if (!function_exists('ai_chat_handle_message')) {
    function ai_chat_handle_message(mysqli $mysqli, array $user, $sessionId, $message)
    {
        $employeeId = (string)($user['employee_id'] ?? '');
        $message = trim((string)$message);
        if ($employeeId === '' || $message === '') {
            return ['success' => false, 'message' => 'Missing employee or message'];
        }

        $sessionId = (int)$sessionId;
        $session = null;
        if ($sessionId > 0) {
            $session = ai_chat_validate_session_owner($mysqli, $sessionId, $employeeId);
            if (!$session) {
                return ['success' => false, 'message' => 'Chat session not found'];
            }
        } else {
            $created = ai_chat_create_session($mysqli, $employeeId, ai_chat_default_session_title($message));
            if (!($created['success'] ?? false)) {
                return $created;
            }
            $session = $created['session'];
            $sessionId = (int)$session['id'];
        }

        ai_chat_insert_message($mysqli, $sessionId, $employeeId, 'user', $message, null, null, null, null);

        if (trim((string)($session['title'] ?? '')) === 'AI Assistant') {
            $countStmt = $mysqli->prepare("SELECT COUNT(*) FROM ai_chat_messages WHERE session_id = ? AND sender_type IN ('user', 'assistant')");
            if ($countStmt) {
                $countStmt->bind_param('i', $sessionId);
                $countStmt->execute();
                $countRes = $countStmt->get_result();
                $messageCount = $countRes ? (int)($countRes->fetch_row()[0] ?? 0) : 0;
                $countStmt->close();
                if ($messageCount <= 1) {
                    $session['title'] = ai_chat_default_session_title($message);
                    ai_chat_touch_session($mysqli, $sessionId, $session['title'], null, null);
                }
            }
        }

        $messages = ai_chat_build_model_messages($mysqli, $user, $sessionId, '');
        $preparedPayload = ai_chat_prepare_reply_payload($mysqli, $user, $messages, $message);
        $storedPayload = ai_chat_store_reply_payload($mysqli, $sessionId, $employeeId, $preparedPayload);

        return [
            'success' => true,
            'session_id' => $sessionId,
            'session_title' => (string)($session['title'] ?? 'AI Assistant'),
            'message_id' => (int)($storedPayload['message_id'] ?? 0),
            'reply' => (string)($storedPayload['reply'] ?? ''),
            'sources' => $storedPayload['sources'] ?? [],
            'tool_trace' => $storedPayload['tool_trace'] ?? [],
            'provider' => (string)($storedPayload['provider'] ?? 'local'),
            'model' => (string)($storedPayload['model'] ?? 'local-fallback'),
        ];
    }
}

if (!function_exists('ai_chat_get_last_regeneratable_exchange')) {
    function ai_chat_get_last_regeneratable_exchange(mysqli $mysqli, $sessionId, $employeeId)
    {
        $userStmt = $mysqli->prepare("SELECT id, message_text
                                      FROM ai_chat_messages
                                      WHERE session_id = ?
                                        AND employee_id = ?
                                        AND sender_type = 'user'
                                      ORDER BY id DESC
                                      LIMIT 1");
        if (!$userStmt) {
            return null;
        }
        $userStmt->bind_param('is', $sessionId, $employeeId);
        $userStmt->execute();
        $userRes = $userStmt->get_result();
        $userRow = $userRes ? $userRes->fetch_assoc() : null;
        $userStmt->close();
        if (!$userRow) {
            return null;
        }

        $userMessageId = (int)($userRow['id'] ?? 0);
        $assistantStmt = $mysqli->prepare("SELECT id, message_text
                                           FROM ai_chat_messages
                                           WHERE session_id = ?
                                             AND employee_id = ?
                                             AND sender_type = 'assistant'
                                             AND id > ?
                                           ORDER BY id DESC
                                           LIMIT 1");
        if (!$assistantStmt) {
            return null;
        }
        $assistantStmt->bind_param('isi', $sessionId, $employeeId, $userMessageId);
        $assistantStmt->execute();
        $assistantRes = $assistantStmt->get_result();
        $assistantRow = $assistantRes ? $assistantRes->fetch_assoc() : null;
        $assistantStmt->close();
        if (!$assistantRow) {
            return null;
        }

        return [
            'user_message_id' => $userMessageId,
            'user_message' => trim((string)($userRow['message_text'] ?? '')),
            'assistant_message_id' => (int)($assistantRow['id'] ?? 0),
            'assistant_message' => trim((string)($assistantRow['message_text'] ?? '')),
        ];
    }
}

if (!function_exists('ai_chat_regenerate_last_reply')) {
    function ai_chat_regenerate_last_reply(mysqli $mysqli, array $user, $sessionId)
    {
        $employeeId = (string)($user['employee_id'] ?? '');
        $sessionId = (int)$sessionId;
        if ($employeeId === '' || $sessionId <= 0) {
            return ['success' => false, 'message' => 'Invalid session or employee'];
        }

        $session = ai_chat_validate_session_owner($mysqli, $sessionId, $employeeId);
        if (!$session) {
            return ['success' => false, 'message' => 'Chat session not found'];
        }

        $exchange = ai_chat_get_last_regeneratable_exchange($mysqli, $sessionId, $employeeId);
        if (!$exchange || trim((string)($exchange['user_message'] ?? '')) === '') {
            return ['success' => false, 'message' => 'No assistant reply available to regenerate'];
        }

        $messages = ai_chat_build_model_messages($mysqli, $user, $sessionId, '', true);
        $preparedPayload = ai_chat_prepare_reply_payload(
            $mysqli,
            $user,
            $messages,
            (string)$exchange['user_message']
        );

        try {
            $mysqli->begin_transaction();

            $deleteStmt = $mysqli->prepare("DELETE FROM ai_chat_messages
                                            WHERE session_id = ?
                                              AND employee_id = ?
                                              AND sender_type IN ('assistant', 'tool')
                                              AND id > ?");
            if (!$deleteStmt) {
                throw new RuntimeException('Prepare failed for regenerate delete');
            }
            $userMessageId = (int)($exchange['user_message_id'] ?? 0);
            $deleteStmt->bind_param('isi', $sessionId, $employeeId, $userMessageId);
            if (!$deleteStmt->execute()) {
                $deleteStmt->close();
                throw new RuntimeException('Failed to replace previous assistant reply');
            }
            $deleteStmt->close();

            $storedPayload = ai_chat_store_reply_payload($mysqli, $sessionId, $employeeId, $preparedPayload);

            $mysqli->commit();

            return [
                'success' => true,
                'session_id' => $sessionId,
                'session_title' => (string)($session['title'] ?? 'AI Assistant'),
                'message_id' => (int)($storedPayload['message_id'] ?? 0),
                'reply' => (string)($storedPayload['reply'] ?? ''),
                'sources' => $storedPayload['sources'] ?? [],
                'tool_trace' => $storedPayload['tool_trace'] ?? [],
                'provider' => (string)($storedPayload['provider'] ?? 'local'),
                'model' => (string)($storedPayload['model'] ?? 'local-fallback'),
                'replaced_assistant_message_id' => (int)($exchange['assistant_message_id'] ?? 0),
            ];
        } catch (Throwable $e) {
            $mysqli->rollback();
            return ['success' => false, 'message' => 'Unable to regenerate the answer right now'];
        }
    }
}
