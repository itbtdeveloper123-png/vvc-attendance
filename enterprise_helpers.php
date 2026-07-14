<?php

if (!function_exists('get_google_maps_api_key')) {
    function get_google_maps_api_key()
    {
        if (defined('GOOGLE_MAPS_API_KEY') && GOOGLE_MAPS_API_KEY !== '') {
            return trim((string) GOOGLE_MAPS_API_KEY);
        }

        return trim((string) (getenv('GOOGLE_MAPS_API_KEY') ?: ''));
    }
}

if (!function_exists('app_system_roles')) {
    function app_system_roles()
    {
        return [
            ['value' => 'Employee', 'label' => 'បុគ្គលិក (Employee)', 'visibility_suffix' => 'skill'],
            ['value' => 'Worker', 'label' => 'កម្មករ (Worker)', 'visibility_suffix' => 'worker'],
            ['value' => 'Skills', 'label' => 'ជំនាញ (Skills)', 'visibility_suffix' => 'skill'],
            ['value' => 'IT', 'label' => 'IT', 'visibility_suffix' => 'skill'],
            ['value' => 'HRM', 'label' => 'ធនធានមនុស្ស (HRM)', 'visibility_suffix' => 'hrm'],
            ['value' => 'Accounting', 'label' => 'គណនេយ្យ (Accounting)', 'visibility_suffix' => 'skill'],
            ['value' => 'Admin', 'label' => 'Admin', 'visibility_suffix' => 'admin'],
            ['value' => 'Store318Head', 'label' => 'ប្រធានហាងទំនិញ 318', 'visibility_suffix' => 'store318_head'],
            ['value' => 'StoreSKKS2Head', 'label' => 'ប្រធានហាង SKKS2', 'visibility_suffix' => 'store_skks2_head'],
            ['value' => 'StoreNR3Head', 'label' => 'ប្រធានហាង NR3', 'visibility_suffix' => 'store_nr3_head'],
            ['value' => 'StoreSKKS2Deputy', 'label' => 'អនុប្រធានហាង SKKS2', 'visibility_suffix' => 'store_skks2_deputy'],
            ['value' => 'StoreNR3Deputy', 'label' => 'អនុប្រធានហាង NR3', 'visibility_suffix' => 'store_nr3_deputy'],
            ['value' => 'WarehousePSPHead', 'label' => 'ប្រធានឃ្លាំង PSP', 'visibility_suffix' => 'warehouse_psp_head'],
            ['value' => 'WarehousePRVHead', 'label' => 'ប្រធានឃ្លាំង PRV', 'visibility_suffix' => 'warehouse_prv_head'],
            ['value' => 'WarehousePSPAssistant', 'label' => 'ជំនួយការប្រធានឃ្លាំង PSP', 'visibility_suffix' => 'warehouse_psp_assistant'],
            ['value' => 'WarehousePRVAssistant', 'label' => 'ជំនួយការប្រធានឃ្លាំង PRV', 'visibility_suffix' => 'warehouse_prv_assistant'],
            ['value' => 'StockGeneralHead', 'label' => 'ប្រធានគ្រប់គ្រងស្តុកទំនិញទូទៅ', 'visibility_suffix' => 'stock_general_head'],
            ['value' => 'GeneralManagerSK', 'label' => 'ប្រធានគ្រប់គ្រងទូទៅ (SK)', 'visibility_suffix' => 'general_manager_sk'],
            ['value' => 'GeneralManagerVVC', 'label' => 'ប្រធានគ្រប់គ្រងទូទៅ (VVC)', 'visibility_suffix' => 'general_manager_vvc'],
            ['value' => 'DirectorGeneral', 'label' => 'អគ្គនាយក', 'visibility_suffix' => 'director_general'],
        ];
    }
}

if (!function_exists('app_system_role_label')) {
    function app_system_role_label($roleValue)
    {
        $roleValue = trim((string) $roleValue);
        foreach (app_system_roles() as $role) {
            if (strcasecmp((string) $role['value'], $roleValue) === 0) {
                return (string) $role['label'];
            }
        }

        return $roleValue !== '' ? $roleValue : 'Employee';
    }
}

if (!function_exists('app_system_role_visibility_suffix')) {
    function app_system_role_visibility_suffix($roleValue)
    {
        $roleValue = trim((string) $roleValue);
        foreach (app_system_roles() as $role) {
            if (strcasecmp((string) $role['value'], $roleValue) === 0) {
                return (string) $role['visibility_suffix'];
            }
        }

        return 'skill';
    }
}

if (!function_exists('app_system_visibility_roles')) {
    function app_system_visibility_roles()
    {
        $roles = [
            ['suffix' => 'skill', 'label' => 'Staff / Employee', 'default_visible' => '1', 'is_custom' => false],
            ['suffix' => 'worker', 'label' => 'Worker', 'default_visible' => '0', 'is_custom' => false],
            ['suffix' => 'hrm', 'label' => 'HRM', 'default_visible' => '1', 'is_custom' => false],
            ['suffix' => 'admin', 'label' => 'Admin', 'default_visible' => '1', 'is_custom' => false],
        ];
        $seen = ['skill' => true, 'worker' => true, 'hrm' => true, 'admin' => true];

        foreach (app_system_roles() as $role) {
            $suffix = (string) ($role['visibility_suffix'] ?? '');
            if ($suffix === '' || isset($seen[$suffix])) {
                continue;
            }

            $roles[] = [
                'suffix' => $suffix,
                'label' => (string) $role['label'],
                'default_visible' => '1',
                'is_custom' => true,
            ];
            $seen[$suffix] = true;
        }

        return $roles;
    }
}

if (!function_exists('app_custom_visibility_roles')) {
    function app_custom_visibility_roles()
    {
        return array_values(array_filter(app_system_visibility_roles(), function ($role) {
            return !empty($role['is_custom']);
        }));
    }
}

if (!function_exists('app_system_visibility_role_suffixes')) {
    function app_system_visibility_role_suffixes()
    {
        return array_values(array_map(function ($role) {
            return (string) $role['suffix'];
        }, app_system_visibility_roles()));
    }
}

if (!function_exists('gps_normalize_point')) {
    function gps_normalize_point($point)
    {
        if (!is_array($point)) {
            return null;
        }

        $lat = $point['latitude'] ?? $point['lat'] ?? null;
        $lng = $point['longitude'] ?? $point['lng'] ?? null;
        if ($lat === null || $lng === null) {
            return null;
        }

        $lat = (float) $lat;
        $lng = (float) $lng;
        if (($lat == 0.0 && $lng == 0.0) || $lat < -90 || $lat > 90 || $lng < -180 || $lng > 180) {
            return null;
        }

        $result = ['lat' => $lat, 'lng' => $lng];
        if (isset($point['accuracy'])) {
            $result['accuracy'] = floatval($point['accuracy']);
        }
        if (isset($point['speed'])) {
            $result['speed'] = floatval($point['speed']);
        }
        return $result;
    }
}

if (!function_exists('gps_haversine_meters')) {
    function gps_haversine_meters($lat1, $lng1, $lat2, $lng2)
    {
        $earthRadiusMeters = 6371000;
        $dLat = deg2rad((float) $lat2 - (float) $lat1);
        $dLng = deg2rad((float) $lng2 - (float) $lng1);

        $a = sin($dLat / 2) * sin($dLat / 2)
            + cos(deg2rad((float) $lat1)) * cos(deg2rad((float) $lat2))
            * sin($dLng / 2) * sin($dLng / 2);
        $c = 2 * atan2(sqrt($a), sqrt(1 - $a));

        return $earthRadiusMeters * $c;
    }
}

if (!function_exists('gps_prepare_route_points')) {
    function gps_prepare_route_points(array $points, $minDistanceMeters = 25.0, $maxPoints = 100)
    {
        $prepared = [];
        $previous = null;
        $last_active_point = null;

        // First pass: filter out bad accuracy points (accuracy > 35m)
        $filtered = [];
        foreach ($points as $point) {
            $normalized = gps_normalize_point($point);
            if ($normalized === null) {
                continue;
            }
            if (isset($normalized['accuracy']) && $normalized['accuracy'] > 35) {
                continue;
            }
            $filtered[] = $normalized;
        }

        // Fallback to original points if filtered leaves too few points
        if (count($filtered) < 2) {
            $filtered = [];
            foreach ($points as $point) {
                $normalized = gps_normalize_point($point);
                if ($normalized !== null) {
                    $filtered[] = $normalized;
                }
            }
        }

        foreach ($filtered as $normalized) {
            $speed = isset($normalized['speed']) ? floatval($normalized['speed']) : null;

            if ($last_active_point !== null) {
                $dist_from_active = gps_haversine_meters(
                    $last_active_point['lat'],
                    $last_active_point['lng'],
                    $normalized['lat'],
                    $normalized['lng']
                );

                // If user is stationary or speed is extremely low, require a larger distance (e.g. 35m) to clear drift jitter.
                $is_stationary = ($speed !== null && $speed < 0.6); // < ~2.1 km/h
                $required_distance = $is_stationary ? 35.0 : $minDistanceMeters;

                if ($dist_from_active < $required_distance) {
                    continue;
                }
            }

            $prepared[] = $normalized;
            $previous = $normalized;
            $last_active_point = $normalized;
        }

        $count = count($prepared);
        if ($count <= 2 || $count <= $maxPoints) {
            return $prepared;
        }

        $downsampled = [$prepared[0]];
        $step = ($count - 1) / ($maxPoints - 1);
        for ($i = 1; $i < $maxPoints - 1; $i++) {
            $index = (int) round($i * $step);
            $index = max(1, min($count - 2, $index));
            $downsampled[] = $prepared[$index];
        }
        $downsampled[] = $prepared[$count - 1];

        $result = [];
        $lastKey = null;
        foreach ($downsampled as $point) {
            $key = $point['lat'] . ',' . $point['lng'];
            if ($key === $lastKey) {
                continue;
            }
            $result[] = $point;
            $lastKey = $key;
        }

        return $result;
    }
}

if (!function_exists('gps_build_snap_batches')) {
    function gps_build_snap_batches(array $points, $maxGapMeters = 300.0, $maxBatchSize = 100)
    {
        $batches = [];
        $current = [];
        $previous = null;

        foreach ($points as $point) {
            if ($previous !== null) {
                $distance = gps_haversine_meters(
                    $previous['lat'],
                    $previous['lng'],
                    $point['lat'],
                    $point['lng']
                );

                if ($distance > $maxGapMeters && count($current) >= 2) {
                    $batches[] = $current;
                    $current = [];
                }
            }

            $current[] = $point;

            if (count($current) >= $maxBatchSize) {
                $batches[] = $current;
                $current = [$point];
            }

            $previous = $point;
        }

        if (count($current) >= 2) {
            $batches[] = $current;
        }

        return $batches;
    }
}

if (!function_exists('gps_append_unique_point')) {
    function gps_append_unique_point(array &$target, array $point, $thresholdMeters = 1.0)
    {
        if (empty($target)) {
            $target[] = $point;
            return;
        }

        $last = $target[count($target) - 1];
        $distance = gps_haversine_meters($last['lat'], $last['lng'], $point['lat'], $point['lng']);
        if ($distance >= $thresholdMeters) {
            $target[] = $point;
        }
    }
}

if (!function_exists('gps_http_get_json')) {
    function gps_http_get_json($url, $timeoutSeconds = 12)
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $timeoutSeconds,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            $body = curl_exec($ch);
            $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError = curl_error($ch);
            curl_close($ch);

            if ($body === false || $httpCode < 200 || $httpCode >= 300) {
                return ['success' => false, 'message' => $curlError ?: ('HTTP ' . $httpCode)];
            }

            $decoded = json_decode((string) $body, true);
            if (!is_array($decoded)) {
                return ['success' => false, 'message' => 'Invalid JSON response'];
            }

            return ['success' => true, 'data' => $decoded];
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $timeoutSeconds,
            ],
        ]);
        $body = @file_get_contents($url, false, $context);
        if ($body === false) {
            return ['success' => false, 'message' => 'Request failed'];
        }

        $decoded = json_decode((string) $body, true);
        if (!is_array($decoded)) {
            return ['success' => false, 'message' => 'Invalid JSON response'];
        }

        return ['success' => true, 'data' => $decoded];
    }
}

if (!function_exists('gps_snap_to_roads_osrm')) {
    function gps_snap_to_roads_osrm(array $points)
    {
        $prepared = $points;
        if (count($prepared) < 2) {
            return [
                'points' => $prepared,
                'source' => 'raw',
                'message' => 'Not enough route points for OSRM.',
            ];
        }

        // Batch coordinates since public OSRM servers limit number of coordinates (typically max 100).
        // We use batches of 40 points with a 1-point overlap.
        $batchSize = 40;
        $snapped = [];
        $errors = [];
        $totalPoints = count($prepared);

        for ($i = 0; $i < $totalPoints; $i += ($batchSize - 1)) {
            $batch = array_slice($prepared, $i, $batchSize);
            if (count($batch) < 2) {
                if (count($batch) === 1) {
                    $snapped[] = $batch[0];
                }
                break;
            }

            $coords = [];
            $radiuses = [];
            foreach ($batch as $pt) {
                $coords[] = $pt['lng'] . ',' . $pt['lat'];
                $acc = isset($pt['accuracy']) ? floatval($pt['accuracy']) : 25;
                if ($acc <= 0) $acc = 25;
                if ($acc > 40) $acc = 40;
                $radiuses[] = $acc;
            }
            $coordsStr = implode(';', $coords);
            $radiusesStr = implode(';', $radiuses);

            // Try OpenStreetMap's stable routing server first, fallback to demo OSRM server
            $url = 'https://routing.openstreetmap.de/routed-car/match/v1/driving/' . $coordsStr . '?overview=full&geometries=geojson&radiuses=' . $radiusesStr;
            $response = gps_http_get_json($url);
            
            if (!$response['success'] || empty($response['data']['matchings'])) {
                $urlOSRM = 'https://router.project-osrm.org/match/v1/driving/' . $coordsStr . '?overview=full&geometries=geojson&radiuses=' . $radiusesStr;
                $response = gps_http_get_json($urlOSRM);
            }
            
            $data = $response['data'] ?? [];
            if ($response['success'] && ($data['code'] ?? '') === 'Ok' && !empty($data['matchings'])) {
                $matching = $data['matchings'][0];
                $coordsList = $matching['geometry']['coordinates'] ?? [];
                foreach ($coordsList as $coord) {
                    if (is_array($coord) && count($coord) >= 2) {
                        $snapped[] = [
                            'lat' => (float) $coord[1],
                            'lng' => (float) $coord[0],
                        ];
                    }
                }
            } else {
                // Fallback to Route API if matching fails: Try OSM route first, fallback to demo OSRM
                $urlRoute = 'https://routing.openstreetmap.de/routed-car/route/v1/driving/' . $coordsStr . '?overview=full&geometries=geojson';
                $responseRoute = gps_http_get_json($urlRoute);
                if (!$responseRoute['success'] || empty($responseRoute['data']['routes'])) {
                    $urlRouteOSRM = 'https://router.project-osrm.org/route/v1/driving/' . $coordsStr . '?overview=full&geometries=geojson';
                    $responseRoute = gps_http_get_json($urlRouteOSRM);
                }
                
                if ($responseRoute['success'] && !empty($responseRoute['data']['routes'])) {
                    $route = $responseRoute['data']['routes'][0];
                    $coordsList = $route['geometry']['coordinates'] ?? [];
                    foreach ($coordsList as $coord) {
                        if (is_array($coord) && count($coord) >= 2) {
                            $snapped[] = [
                                'lat' => (float) $coord[1],
                                'lng' => (float) $coord[0],
                            ];
                        }
                    }
                } else {
                    $errors[] = $data['message'] ?? 'OSRM match and route failed';
                    foreach ($batch as $pt) {
                        $snapped[] = $pt;
                    }
                }
            }
        }

        $finalPoints = [];
        foreach ($snapped as $pt) {
            gps_append_unique_point($finalPoints, $pt, 1.0);
        }

        if (count($finalPoints) < 2) {
            return [
                'points' => $prepared,
                'source' => 'raw',
                'message' => 'OSRM snapping resulted in no usable path.',
            ];
        }

        return [
            'points' => $finalPoints,
            'source' => 'osrm',
            'message' => empty($errors) ? null : implode('; ', array_unique($errors)),
        ];
    }
}

if (!function_exists('gps_snap_trip_points_to_roads')) {
    function gps_snap_trip_points_to_roads(array $points, $apiKey = null)
    {
        $prepared = gps_prepare_route_points($points);
        if (count($prepared) < 2) {
            return [
                'points' => $prepared,
                'source' => 'raw',
                'message' => 'Not enough route points to snap.',
            ];
        }

        $apiKey = trim((string) ($apiKey ?: get_google_maps_api_key()));
        if ($apiKey === '' || $apiKey === 'AIzaSyBTlrKycJRtWAU7mRzlfrCEeC6GCWgQERA') {
            return gps_snap_to_roads_osrm($prepared);
        }

        $batches = gps_build_snap_batches($prepared);
        if (empty($batches)) {
            return gps_snap_to_roads_osrm($prepared);
        }

        $snapped = [];
        $errors = [];

        foreach ($batches as $batch) {
            $path = implode('|', array_map(static function ($point) {
                return $point['lat'] . ',' . $point['lng'];
            }, $batch));

            $url = 'https://roads.googleapis.com/v1/snapToRoads?interpolate=true&path='
                . rawurlencode($path)
                . '&key=' . rawurlencode($apiKey);

            $response = gps_http_get_json($url);
            if (!$response['success']) {
                $errors[] = $response['message'] ?? 'Unknown error';
                foreach ($batch as $point) {
                    gps_append_unique_point($snapped, $point);
                }
                continue;
            }

            $payload = $response['data'] ?? [];
            $snapPoints = $payload['snappedPoints'] ?? [];
            if (!is_array($snapPoints) || empty($snapPoints)) {
                $errors[] = $payload['error']['message'] ?? 'No snapped points returned';
                foreach ($batch as $point) {
                    gps_append_unique_point($snapped, $point);
                }
                continue;
            }

            foreach ($snapPoints as $snapPoint) {
                if (!isset($snapPoint['location']['latitude'], $snapPoint['location']['longitude'])) {
                    continue;
                }

                gps_append_unique_point($snapped, [
                    'lat' => (float) $snapPoint['location']['latitude'],
                    'lng' => (float) $snapPoint['location']['longitude'],
                ]);
            }
        }

        if (count($snapped) < 2 || !empty($errors)) {
            $osrmResult = gps_snap_to_roads_osrm($prepared);
            if ($osrmResult['source'] === 'osrm') {
                return $osrmResult;
            }
        }

        if (count($snapped) < 2) {
            return [
                'points' => $prepared,
                'source' => 'raw',
                'message' => !empty($errors) ? implode('; ', array_unique($errors)) : 'Road snapping returned no usable path.',
            ];
        }

        return [
            'points' => $snapped,
            'source' => empty($errors) ? 'roads' : 'roads_partial',
            'message' => !empty($errors) ? implode('; ', array_unique($errors)) : null,
        ];
    }
}

if (!function_exists('enterprise_json_encode')) {
    function enterprise_json_encode($value)
    {
        $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return ($json === false) ? '[]' : $json;
    }
}

if (!function_exists('enterprise_parse_json_list')) {
    function enterprise_parse_json_list($value)
    {
        if (is_array($value)) {
            return array_values(array_filter(array_map(static function ($item) {
                return trim((string) $item);
            }, $value), static function ($item) {
                return $item !== '';
            }));
        }

        $decoded = json_decode((string) $value, true);
        if (is_array($decoded)) {
            return enterprise_parse_json_list($decoded);
        }

        $parts = preg_split('/[\r\n,]+/', (string) $value, -1, PREG_SPLIT_NO_EMPTY);
        return array_values(array_filter(array_map('trim', $parts), static function ($item) {
            return $item !== '';
        }));
    }
}

if (!function_exists('ensure_request_workflow_logs_table')) {
    function ensure_request_workflow_logs_table($mysqli)
    {
        $mysqli->query("CREATE TABLE IF NOT EXISTS request_workflow_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            request_id INT NOT NULL,
            action_type VARCHAR(64) NOT NULL,
            status_from VARCHAR(64) DEFAULT NULL,
            status_to VARCHAR(64) DEFAULT NULL,
            actor_id VARCHAR(100) DEFAULT NULL,
            actor_name VARCHAR(255) DEFAULT NULL,
            actor_role VARCHAR(100) DEFAULT NULL,
            note TEXT DEFAULT NULL,
            meta_json LONGTEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_request_created (request_id, created_at),
            KEY idx_request_action (request_id, action_type)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
}

if (!function_exists('ensure_stock_movements_table')) {
    function ensure_stock_movements_table($mysqli)
    {
        $mysqli->query("CREATE TABLE IF NOT EXISTS stock_movements (
            id INT AUTO_INCREMENT PRIMARY KEY,
            admin_id VARCHAR(64) DEFAULT 'SYSTEM_WIDE',
            item_id INT NOT NULL,
            item_name VARCHAR(255) DEFAULT '',
            movement_type VARCHAR(64) NOT NULL,
            quantity_change INT NOT NULL DEFAULT 0,
            quantity_before INT NOT NULL DEFAULT 0,
            quantity_after INT NOT NULL DEFAULT 0,
            reference_type VARCHAR(64) DEFAULT NULL,
            reference_id INT DEFAULT NULL,
            reference_no VARCHAR(120) DEFAULT NULL,
            unit_price DECIMAL(15,2) DEFAULT NULL,
            total_value DECIMAL(15,2) DEFAULT NULL,
            location VARCHAR(255) DEFAULT NULL,
            notes TEXT DEFAULT NULL,
            actor_name VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_item_created (item_id, created_at),
            KEY idx_movement_type (movement_type),
            KEY idx_reference (reference_type, reference_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
}

if (!function_exists('ensure_notification_template_tables')) {
    function ensure_notification_template_tables($mysqli)
    {
        $mysqli->query("CREATE TABLE IF NOT EXISTS notification_templates (
            id INT AUTO_INCREMENT PRIMARY KEY,
            admin_id VARCHAR(64) NOT NULL DEFAULT 'SYSTEM_WIDE',
            template_key VARCHAR(120) DEFAULT NULL,
            template_name VARCHAR(255) NOT NULL,
            title_template VARCHAR(255) NOT NULL,
            message_template TEXT NOT NULL,
            target_type ENUM('all','role','user') NOT NULL DEFAULT 'all',
            target_roles_json LONGTEXT DEFAULT NULL,
            target_users_json LONGTEXT DEFAULT NULL,
            image_url VARCHAR(255) DEFAULT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_admin_active (admin_id, is_active),
            KEY idx_template_key (template_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $mysqli->query("CREATE TABLE IF NOT EXISTS notification_schedules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            admin_id VARCHAR(64) NOT NULL DEFAULT 'SYSTEM_WIDE',
            template_id INT DEFAULT NULL,
            schedule_name VARCHAR(255) NOT NULL,
            title_override VARCHAR(255) DEFAULT NULL,
            message_override TEXT DEFAULT NULL,
            target_type ENUM('all','role','user') DEFAULT NULL,
            target_roles_json LONGTEXT DEFAULT NULL,
            target_users_json LONGTEXT DEFAULT NULL,
            image_url VARCHAR(255) DEFAULT NULL,
            frequency ENUM('once','daily','weekly','monthly') NOT NULL DEFAULT 'once',
            scheduled_at DATETIME DEFAULT NULL,
            time_of_day VARCHAR(5) DEFAULT NULL,
            day_of_week TINYINT DEFAULT NULL,
            day_of_month TINYINT DEFAULT NULL,
            next_run_at DATETIME DEFAULT NULL,
            last_run_at DATETIME DEFAULT NULL,
            last_result VARCHAR(32) DEFAULT NULL,
            last_message TEXT DEFAULT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_next_run (is_active, next_run_at),
            KEY idx_schedule_admin (admin_id, is_active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
}

if (!function_exists('ensure_enterprise_support_tables')) {
    function ensure_enterprise_support_tables($mysqli)
    {
        ensure_request_workflow_logs_table($mysqli);
        ensure_stock_movements_table($mysqli);
        ensure_notification_template_tables($mysqli);
    }
}

if (!function_exists('add_request_workflow_log')) {
    function add_request_workflow_log($mysqli, $requestId, $actionType, $statusFrom = null, $statusTo = null, $actorId = '', $actorName = '', $actorRole = '', $note = '', array $meta = [])
    {
        ensure_request_workflow_logs_table($mysqli);

        $requestId = (int) $requestId;
        if ($requestId <= 0) {
            return false;
        }

        $metaJson = !empty($meta) ? enterprise_json_encode($meta) : null;
        $sql = "INSERT INTO request_workflow_logs
                (request_id, action_type, status_from, status_to, actor_id, actor_name, actor_role, note, meta_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        if (!($stmt = $mysqli->prepare($sql))) {
            return false;
        }

        $stmt->bind_param(
            "issssssss",
            $requestId,
            $actionType,
            $statusFrom,
            $statusTo,
            $actorId,
            $actorName,
            $actorRole,
            $note,
            $metaJson
        );
        $ok = $stmt->execute();
        $stmt->close();
        return $ok;
    }
}

if (!function_exists('build_request_workflow_timeline')) {
    function build_request_workflow_timeline($mysqli, $requestId)
    {
        ensure_request_workflow_logs_table($mysqli);

        $requestId = (int) $requestId;
        if ($requestId <= 0) {
            return ['request' => null, 'timeline' => []];
        }

        $request = null;
        $sql = "SELECT r.*, u.employee_id, u.name AS employee_name, u.avatar
                FROM requests r
                LEFT JOIN users u ON r.user_id = u.id
                WHERE r.id = ?
                LIMIT 1";
        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("i", $requestId);
            $stmt->execute();
            $res = $stmt->get_result();
            $request = $res ? $res->fetch_assoc() : null;
            $stmt->close();
        }

        $timeline = [];
        if ($stmt = $mysqli->prepare("SELECT * FROM request_workflow_logs WHERE request_id = ? ORDER BY created_at ASC, id ASC")) {
            $stmt->bind_param("i", $requestId);
            $stmt->execute();
            $res = $stmt->get_result();
            while ($res && $row = $res->fetch_assoc()) {
                $row['meta'] = json_decode((string) ($row['meta_json'] ?? ''), true) ?: [];
                unset($row['meta_json']);
                $timeline[] = $row;
            }
            $stmt->close();
        }

        if ($request && empty($timeline)) {
            $timeline[] = [
                'action_type' => 'created',
                'status_from' => null,
                'status_to' => 'pending',
                'actor_id' => (string) ($request['employee_id'] ?? ''),
                'actor_name' => (string) ($request['requester_name'] ?? $request['employee_name'] ?? ''),
                'actor_role' => 'Requester',
                'note' => 'Request submitted',
                'created_at' => (string) ($request['created_at'] ?? ''),
                'meta' => [],
            ];

            if (!empty($request['department_head_signature_date']) || !empty($request['department_head_name'])) {
                $timeline[] = [
                    'action_type' => 'department_review',
                    'status_from' => 'pending',
                    'status_to' => 'pending',
                    'actor_id' => '',
                    'actor_name' => (string) ($request['department_head_name'] ?? ''),
                    'actor_role' => 'Department Head',
                    'note' => 'Department review/signature captured',
                    'created_at' => (string) ($request['department_head_signature_date'] ?? $request['created_at'] ?? ''),
                    'meta' => [],
                ];
            }

            if (!empty($request['approved_at']) || in_array(strtolower((string) ($request['status'] ?? '')), ['approved', 'rejected'], true)) {
                $timeline[] = [
                    'action_type' => strtolower((string) ($request['status'] ?? 'pending')) === 'approved' ? 'approved' : 'rejected',
                    'status_from' => 'pending',
                    'status_to' => (string) ($request['status'] ?? ''),
                    'actor_id' => '',
                    'actor_name' => (string) ($request['approved_by'] ?? ''),
                    'actor_role' => 'Admin',
                    'note' => (string) ($request['admin_comment'] ?? ''),
                    'created_at' => (string) ($request['approved_at'] ?? $request['created_at'] ?? ''),
                    'meta' => [],
                ];
            }
        }

        return ['request' => $request, 'timeline' => $timeline];
    }
}

if (!function_exists('record_stock_movement')) {
    function record_stock_movement($mysqli, array $movement)
    {
        ensure_stock_movements_table($mysqli);

        $itemId = (int) ($movement['item_id'] ?? 0);
        if ($itemId <= 0) {
            return false;
        }

        $adminId = (string) ($movement['admin_id'] ?? 'SYSTEM_WIDE');
        $itemName = (string) ($movement['item_name'] ?? '');
        $movementType = (string) ($movement['movement_type'] ?? 'adjustment');
        $qtyChange = (int) ($movement['quantity_change'] ?? 0);
        $qtyBefore = (int) ($movement['quantity_before'] ?? 0);
        $qtyAfter = (int) ($movement['quantity_after'] ?? 0);
        $referenceType = (string) ($movement['reference_type'] ?? '');
        $referenceId = isset($movement['reference_id']) ? (int) $movement['reference_id'] : null;
        $referenceNo = (string) ($movement['reference_no'] ?? '');
        $unitPrice = isset($movement['unit_price']) && $movement['unit_price'] !== '' ? (float) $movement['unit_price'] : null;
        $totalValue = isset($movement['total_value']) && $movement['total_value'] !== '' ? (float) $movement['total_value'] : null;
        $location = (string) ($movement['location'] ?? '');
        $notes = (string) ($movement['notes'] ?? '');
        $actorName = (string) ($movement['actor_name'] ?? '');

        $sql = "INSERT INTO stock_movements
                (admin_id, item_id, item_name, movement_type, quantity_change, quantity_before, quantity_after,
                 reference_type, reference_id, reference_no, unit_price, total_value, location, notes, actor_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        if (!($stmt = $mysqli->prepare($sql))) {
            return false;
        }

        $stmt->bind_param(
            "sissiiisisddsss",
            $adminId,
            $itemId,
            $itemName,
            $movementType,
            $qtyChange,
            $qtyBefore,
            $qtyAfter,
            $referenceType,
            $referenceId,
            $referenceNo,
            $unitPrice,
            $totalValue,
            $location,
            $notes,
            $actorName
        );
        $ok = $stmt->execute();
        $stmt->close();
        return $ok;
    }
}

if (!function_exists('apply_notification_placeholders')) {
    function apply_notification_placeholders($text, array $context = [])
    {
        $text = (string) $text;
        if ($text === '') {
            return '';
        }

        $defaults = [
            'today' => date('Y-m-d'),
            'date' => date('Y-m-d'),
            'time' => date('H:i'),
        ];
        $context = array_merge($defaults, $context);

        foreach ($context as $key => $value) {
            $text = str_replace('{{' . $key . '}}', (string) $value, $text);
        }

        return $text;
    }
}

if (!function_exists('compute_notification_schedule_next_run')) {
    function compute_notification_schedule_next_run($frequency, $scheduledAt = null, $timeOfDay = null, $dayOfWeek = null, $dayOfMonth = null, $fromTime = null)
    {
        $tz = new DateTimeZone('Asia/Phnom_Penh');
        $base = $fromTime ? new DateTimeImmutable((string) $fromTime, $tz) : new DateTimeImmutable('now', $tz);
        $frequency = strtolower(trim((string) $frequency));
        $timeOfDay = preg_match('/^\d{2}:\d{2}$/', (string) $timeOfDay) ? $timeOfDay : '09:00';

        if ($frequency === 'once') {
            if (empty($scheduledAt)) {
                return null;
            }
            try {
                $dt = new DateTimeImmutable((string) $scheduledAt, $tz);
                return $dt->format('Y-m-d H:i:s');
            } catch (Throwable $e) {
                return null;
            }
        }

        if ($frequency === 'daily') {
            $candidate = new DateTimeImmutable($base->format('Y-m-d') . ' ' . $timeOfDay . ':00', $tz);
            if ($candidate <= $base) {
                $candidate = $candidate->modify('+1 day');
            }
            return $candidate->format('Y-m-d H:i:s');
        }

        if ($frequency === 'weekly') {
            $targetDow = is_numeric($dayOfWeek) ? max(0, min(6, (int) $dayOfWeek)) : (int) $base->format('w');
            $candidate = new DateTimeImmutable($base->format('Y-m-d') . ' ' . $timeOfDay . ':00', $tz);
            $currentDow = (int) $candidate->format('w');
            $diff = $targetDow - $currentDow;
            if ($diff < 0 || ($diff === 0 && $candidate <= $base)) {
                $diff += 7;
            }
            $candidate = $candidate->modify('+' . $diff . ' day');
            return $candidate->format('Y-m-d H:i:s');
        }

        if ($frequency === 'monthly') {
            $targetDay = is_numeric($dayOfMonth) ? max(1, min(31, (int) $dayOfMonth)) : (int) $base->format('d');
            $year = (int) $base->format('Y');
            $month = (int) $base->format('m');

            for ($i = 0; $i < 13; $i++) {
                $monthStart = (new DateTimeImmutable(sprintf('%04d-%02d-01 %s:00', $year, $month, $timeOfDay), $tz));
                $daysInMonth = (int) $monthStart->format('t');
                $candidateDay = min($targetDay, $daysInMonth);
                $candidate = new DateTimeImmutable(sprintf('%04d-%02d-%02d %s:00', $year, $month, $candidateDay, $timeOfDay), $tz);
                if ($candidate > $base) {
                    return $candidate->format('Y-m-d H:i:s');
                }
                $month++;
                if ($month > 12) {
                    $month = 1;
                    $year++;
                }
            }
        }

        return null;
    }
}

if (!function_exists('dispatch_notification_schedule')) {
    function dispatch_notification_schedule($mysqli, array $schedule)
    {
        $template = null;
        $templateId = (int) ($schedule['template_id'] ?? 0);
        if ($templateId > 0 && ($stmt = $mysqli->prepare("SELECT * FROM notification_templates WHERE id = ? LIMIT 1"))) {
            $stmt->bind_param("i", $templateId);
            $stmt->execute();
            $res = $stmt->get_result();
            $template = $res ? $res->fetch_assoc() : null;
            $stmt->close();
        }

        $context = [
            'schedule_name' => (string) ($schedule['schedule_name'] ?? ''),
            'admin_id' => (string) ($schedule['admin_id'] ?? ''),
        ];

        $title = trim((string) ($schedule['title_override'] ?? ''));
        if ($title === '' && $template) {
            $title = trim((string) ($template['title_template'] ?? ''));
        }
        $title = apply_notification_placeholders($title, $context);

        $message = trim((string) ($schedule['message_override'] ?? ''));
        if ($message === '' && $template) {
            $message = trim((string) ($template['message_template'] ?? ''));
        }
        $message = apply_notification_placeholders($message, $context);

        $targetType = trim((string) ($schedule['target_type'] ?? ''));
        if ($targetType === '' && $template) {
            $targetType = (string) ($template['target_type'] ?? 'all');
        }
        if ($targetType === '') {
            $targetType = 'all';
        }

        $roles = enterprise_parse_json_list($schedule['target_roles_json'] ?? '');
        if (empty($roles) && $template) {
            $roles = enterprise_parse_json_list($template['target_roles_json'] ?? '');
        }
        $users = enterprise_parse_json_list($schedule['target_users_json'] ?? '');
        if (empty($users) && $template) {
            $users = enterprise_parse_json_list($template['target_users_json'] ?? '');
        }

        $imageUrl = trim((string) ($schedule['image_url'] ?? ''));
        if ($imageUrl === '' && $template) {
            $imageUrl = trim((string) ($template['image_url'] ?? ''));
        }

        if ($title === '' || $message === '') {
            return ['success' => false, 'message' => 'Schedule is missing title or message.'];
        }

        $adminId = (string) ($schedule['admin_id'] ?? 'SYSTEM_WIDE');
        if ($targetType === 'role') {
            if (empty($roles) || !function_exists('sendAppNotificationToRoles')) {
                return ['success' => false, 'message' => 'No roles configured for this schedule.'];
            }
            $ok = sendAppNotificationToRoles($mysqli, $roles, $title, $message, $adminId, null, $imageUrl, [
                'type' => 'scheduled_notification',
                'schedule_id' => (string) ($schedule['id'] ?? ''),
            ]);
            return ['success' => (bool) $ok, 'message' => $ok ? 'Notification sent to selected roles.' : 'Role notification failed.'];
        }

        if ($targetType === 'user') {
            if (empty($users) || !function_exists('sendAppNotificationToUser')) {
                return ['success' => false, 'message' => 'No users configured for this schedule.'];
            }

            $sent = 0;
            foreach ($users as $employeeId) {
                if (sendAppNotificationToUser($mysqli, $employeeId, $title, $message, $adminId, null, $imageUrl)) {
                    $sent++;
                }
            }
            return ['success' => ($sent > 0), 'message' => $sent > 0 ? ('Notification sent to ' . $sent . ' users.') : 'User notification failed.'];
        }

        if (!function_exists('sendAppNotificationToAll')) {
            return ['success' => false, 'message' => 'Notification sender is unavailable.'];
        }
        $ok = sendAppNotificationToAll($mysqli, $title, $message, $adminId, null, $imageUrl, [
            'type' => 'scheduled_notification',
            'schedule_id' => (string) ($schedule['id'] ?? ''),
        ]);
        return ['success' => (bool) $ok, 'message' => $ok ? 'Notification broadcast completed.' : 'Broadcast failed.'];
    }
}

if (!function_exists('process_due_notification_schedules')) {
    function process_due_notification_schedules($mysqli, $limit = 3)
    {
        if (!function_exists('sendAppNotificationToAll') || !function_exists('sendAppNotificationToRoles') || !function_exists('sendAppNotificationToUser')) {
            return;
        }

        ensure_notification_template_tables($mysqli);

        $limit = max(1, min(10, (int) $limit));
        $now = date('Y-m-d H:i:s');
        $schedules = [];

        if ($stmt = $mysqli->prepare("SELECT * FROM notification_schedules WHERE is_active = 1 AND next_run_at IS NOT NULL AND next_run_at <= ? ORDER BY next_run_at ASC LIMIT ?")) {
            $stmt->bind_param("si", $now, $limit);
            $stmt->execute();
            $res = $stmt->get_result();
            while ($res && $row = $res->fetch_assoc()) {
                $schedules[] = $row;
            }
            $stmt->close();
        }

        foreach ($schedules as $schedule) {
            $result = dispatch_notification_schedule($mysqli, $schedule);
            $nextRunAt = null;
            $isActive = !empty($schedule['is_active']) ? 1 : 0;

            if (!empty($result['success'])) {
                if (($schedule['frequency'] ?? 'once') === 'once') {
                    $isActive = 0;
                } else {
                    $nextRunAt = compute_notification_schedule_next_run(
                        $schedule['frequency'] ?? 'once',
                        $schedule['scheduled_at'] ?? null,
                        $schedule['time_of_day'] ?? null,
                        $schedule['day_of_week'] ?? null,
                        $schedule['day_of_month'] ?? null,
                        date('Y-m-d H:i:s', time() + 60)
                    );
                }
            } else {
                $nextRunAt = date('Y-m-d H:i:s', time() + 600);
            }

            if ($stmt = $mysqli->prepare("UPDATE notification_schedules SET last_run_at = NOW(), next_run_at = ?, is_active = ?, last_result = ?, last_message = ? WHERE id = ?")) {
                $lastResult = !empty($result['success']) ? 'success' : 'error';
                $lastMessage = (string) ($result['message'] ?? '');
                $scheduleId = (int) ($schedule['id'] ?? 0);
                $stmt->bind_param("sissi", $nextRunAt, $isActive, $lastResult, $lastMessage, $scheduleId);
                $stmt->execute();
                $stmt->close();
            }
        }
    }
}
