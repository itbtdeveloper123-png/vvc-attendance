<?php

if (!function_exists('ai_chat_is_admin_like')) {
    function ai_chat_is_admin_like(array $user)
    {
        $systemRole = strtolower((string)($user['system_role'] ?? ''));
        $userRole = strtolower((string)($user['user_role'] ?? ''));
        return in_array($systemRole, ['admin', 'hrm'], true) || in_array($userRole, ['admin', 'hrm'], true);
    }
}

if (!function_exists('ai_chat_get_tool_definitions')) {
    function ai_chat_get_tool_definitions(array $user)
    {
        $tools = [
            [
                'type' => 'function',
                'function' => [
                    'name' => 'get_my_attendance_today',
                    'description' => 'Get the current user attendance scans for today, including first check-in, latest action, status, and location.',
                    'parameters' => [
                        'type' => 'object',
                        'properties' => new stdClass(),
                    ],
                ],
            ],
            [
                'type' => 'function',
                'function' => [
                    'name' => 'get_my_leave_balance',
                    'description' => 'Get the current user remaining annual leave balance and basic profile info.',
                    'parameters' => [
                        'type' => 'object',
                        'properties' => new stdClass(),
                    ],
                ],
            ],
            [
                'type' => 'function',
                'function' => [
                    'name' => 'get_my_requests',
                    'description' => 'Get the current user recent requests and pending request count.',
                    'parameters' => [
                        'type' => 'object',
                        'properties' => [
                            'status' => [
                                'type' => 'string',
                                'description' => 'Optional request status filter such as pending, approved, or rejected.',
                            ],
                            'limit' => [
                                'type' => 'integer',
                                'description' => 'How many recent requests to return. Use a small number.',
                            ],
                        ],
                    ],
                ],
            ],
        ];

        if (ai_chat_is_admin_like($user)) {
            $tools[] = [
                'type' => 'function',
                'function' => [
                    'name' => 'get_team_pending_requests',
                    'description' => 'Get a summary of pending requests across the team for Admin or HRM users.',
                    'parameters' => [
                        'type' => 'object',
                        'properties' => [
                            'limit' => [
                                'type' => 'integer',
                                'description' => 'How many recent pending requests to return. Use a small number.',
                            ],
                        ],
                    ],
                ],
            ];
        }

        return $tools;
    }
}

if (!function_exists('ai_chat_execute_tool')) {
    function ai_chat_execute_tool(mysqli $mysqli, array $user, $toolName, array $args = [])
    {
        switch ($toolName) {
            case 'get_my_attendance_today':
                return ai_chat_tool_attendance_today($mysqli, $user);

            case 'get_my_leave_balance':
                return ai_chat_tool_leave_balance($mysqli, $user);

            case 'get_my_requests':
                return ai_chat_tool_my_requests($mysqli, $user, $args);

            case 'get_team_pending_requests':
                if (!ai_chat_is_admin_like($user)) {
                    return [
                        'ok' => false,
                        'message' => 'Permission denied for team pending requests.',
                    ];
                }
                return ai_chat_tool_team_pending_requests($mysqli, $args);
        }

        return [
            'ok' => false,
            'message' => 'Unsupported tool: ' . $toolName,
        ];
    }
}

if (!function_exists('ai_chat_tool_attendance_today')) {
    function ai_chat_tool_attendance_today(mysqli $mysqli, array $user)
    {
        $eid = (string)($user['employee_id'] ?? '');
        $sql = "SELECT action_type, status, location_name,
                       DATE_FORMAT(log_datetime, '%h:%i %p') AS log_time,
                       DATE_FORMAT(log_datetime, '%Y-%m-%d %H:%i:%s') AS raw_time
                FROM checkin_logs
                WHERE employee_id = ?
                  AND log_datetime >= CURDATE()
                  AND log_datetime < DATE_ADD(CURDATE(), INTERVAL 1 DAY)
                ORDER BY log_datetime ASC";
        $stmt = $mysqli->prepare($sql);
        if (!$stmt) {
            return ['ok' => false, 'message' => 'Prepare failed'];
        }
        $stmt->bind_param('s', $eid);
        $stmt->execute();
        $res = $stmt->get_result();
        $rows = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $rows[] = $row;
            }
        }
        $stmt->close();

        $firstCheckIn = null;
        $latest = null;
        foreach ($rows as $row) {
            $latest = $row;
            if ($firstCheckIn === null && stripos((string)$row['action_type'], 'in') !== false) {
                $firstCheckIn = $row;
            }
        }

        return [
            'ok' => true,
            'date' => date('Y-m-d'),
            'total_scans' => count($rows),
            'first_check_in' => $firstCheckIn,
            'latest_scan' => $latest,
            'scans' => array_slice($rows, 0, 10),
        ];
    }
}

if (!function_exists('ai_chat_tool_leave_balance')) {
    function ai_chat_tool_leave_balance(mysqli $mysqli, array $user)
    {
        $eid = (string)($user['employee_id'] ?? '');
        $sql = "SELECT employee_id, name, position, department, branch,
                       COALESCE(annual_leave_balance, 0) AS annual_leave_balance
                FROM users
                WHERE employee_id = ?
                LIMIT 1";
        $stmt = $mysqli->prepare($sql);
        if (!$stmt) {
            return ['ok' => false, 'message' => 'Prepare failed'];
        }
        $stmt->bind_param('s', $eid);
        $stmt->execute();
        $res = $stmt->get_result();
        $row = $res ? $res->fetch_assoc() : null;
        $stmt->close();

        if (!$row) {
            return ['ok' => false, 'message' => 'User not found'];
        }

        return [
            'ok' => true,
            'profile' => $row,
            'annual_leave_balance' => (float)$row['annual_leave_balance'],
        ];
    }
}

if (!function_exists('ai_chat_tool_my_requests')) {
    function ai_chat_tool_my_requests(mysqli $mysqli, array $user, array $args = [])
    {
        $uid = (int)($user['id'] ?? 0);
        $status = strtolower(trim((string)($args['status'] ?? '')));
        $limit = (int)($args['limit'] ?? 5);
        if ($uid <= 0) {
            return ['ok' => false, 'message' => 'User ID not found'];
        }
        if ($limit <= 0) {
            $limit = 5;
        }
        if ($limit > 10) {
            $limit = 10;
        }

        $sql = "SELECT id, request_type, status, reason,
                       DATE_FORMAT(request_date, '%Y-%m-%d') AS request_date,
                       DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at
                FROM requests
                WHERE user_id = ?";
        $types = 'i';
        $params = [$uid];

        if ($status !== '' && in_array($status, ['pending', 'approved', 'rejected'], true)) {
            $sql .= " AND status = ?";
            $types .= 's';
            $params[] = $status;
        }

        $sql .= " ORDER BY id DESC LIMIT ?";
        $types .= 'i';
        $params[] = $limit;

        $stmt = $mysqli->prepare($sql);
        if (!$stmt) {
            return ['ok' => false, 'message' => 'Prepare failed'];
        }
        $bindValues = [];
        $bindValues[] = $types;
        foreach ($params as $key => $value) {
            $bindValues[] = &$params[$key];
        }
        call_user_func_array([$stmt, 'bind_param'], $bindValues);
        $stmt->execute();
        $res = $stmt->get_result();
        $items = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $row['reason'] = mb_substr((string)($row['reason'] ?? ''), 0, 180, 'UTF-8');
                $items[] = $row;
            }
        }
        $stmt->close();

        $pendingCount = 0;
        $stmt = $mysqli->prepare("SELECT COUNT(*) FROM requests WHERE user_id = ? AND status = 'pending'");
        if ($stmt) {
            $stmt->bind_param('i', $uid);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($res) {
                $pendingCount = (int)($res->fetch_row()[0] ?? 0);
            }
            $stmt->close();
        }

        return [
            'ok' => true,
            'pending_count' => $pendingCount,
            'items' => $items,
            'filter_status' => $status,
        ];
    }
}

if (!function_exists('ai_chat_tool_team_pending_requests')) {
    function ai_chat_tool_team_pending_requests(mysqli $mysqli, array $args = [])
    {
        $limit = (int)($args['limit'] ?? 5);
        if ($limit <= 0) {
            $limit = 5;
        }
        if ($limit > 10) {
            $limit = 10;
        }

        $summary = [
            'ok' => true,
            'pending_count' => 0,
            'items' => [],
        ];

        $res = $mysqli->query("SELECT COUNT(*) AS pending_count FROM requests WHERE status = 'pending'");
        if ($res && $row = $res->fetch_assoc()) {
            $summary['pending_count'] = (int)($row['pending_count'] ?? 0);
        }

        $stmt = $mysqli->prepare("SELECT requester_name, request_type, status,
                                         DATE_FORMAT(request_date, '%Y-%m-%d') AS request_date,
                                         LEFT(COALESCE(reason, ''), 180) AS reason
                                  FROM requests
                                  WHERE status = 'pending'
                                  ORDER BY id DESC
                                  LIMIT ?");
        if ($stmt) {
            $stmt->bind_param('i', $limit);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($res) {
                while ($row = $res->fetch_assoc()) {
                    $summary['items'][] = $row;
                }
            }
            $stmt->close();
        }

        return $summary;
    }
}
