<?php
date_default_timezone_set('Asia/Phnom_Penh');
ob_start();
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once __DIR__ . '/config.php';

$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_error) {
    die('Connection failed: ' . $mysqli->connect_error);
}
$mysqli->set_charset('utf8mb4');
$mysqli->query("SET time_zone = '+07:00'");

if (isset($_POST['ajax_action'])) {
    $ajax_action = $_POST['ajax_action'];
    switch ($ajax_action) {
            case 'update_single_attendance':
                header('Content-Type: application/json');
                $date = $_POST['date'] ?? null;
                $column = $_POST['column'] ?? null;
                $value = isset($_POST['value']) ? (int)$_POST['value'] : 0;
                $store = $_POST['store'] ?? 'ks2'; 

                if (!$date || !$column) {
                    echo json_encode(['success' => false, 'message' => 'ទិន្នន័យមិនត្រឹមត្រូវ។']);
                    exit();
                }

                $main_tables = ['ks2' => 'ks2_consolidated_staff', 'nr3' => 'nr3_consolidated_staff', '318' => 'store_318_consolidated_staff'];
                $table = $main_tables[$store] ?? 'ks2_consolidated_staff';

                // Basic validation: must be a valid column name ending with _female or _male or _morning/_evening
                if (!preg_match('/^[a-z0-9_]+$/i', $column)) {
                    echo json_encode(['success' => false, 'message' => 'Invalid column.']);
                    exit();
                }

                try {
                    $sql = "INSERT INTO {$table} (reports_date, {$column}) VALUES (?, ?) ON DUPLICATE KEY UPDATE {$column} = ?";
                    if ($stmt = $mysqli->prepare($sql)) {
                        $stmt->bind_param("sii", $date, $value, $value);
                        $stmt->execute();
                        $stmt->close();
                        echo json_encode(['success' => true, 'message' => 'រក្សាទុកទិន្នន័យរួចរាល់!']);
                    } else {
                        echo json_encode(['success' => false, 'message' => 'Query Error']);
                    }
                } catch (Exception $e) {
                    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
                }
                exit();

            case 'update_leave_deo_inline':
                header('Content-Type: application/json');
                $id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
                $column = $_POST['column'] ?? null;
                $value = $_POST['value'] ?? '';
                $store = $_POST['store'] ?? 'ks2'; // ks2, nr3, 318
                
                $table_map = [
                    'ks2' => 'ks2_new_staff',
                    'nr3' => 'nr3_new_staff',
                    '318' => 'store_318_new_staff'
                ];
                $table = $table_map[$store] ?? 'ks2_new_staff';

                $allowed_columns = ['number', 'name', 'role', 'note', 'reports_date'];
                if (!$id || !$column || !in_array($column, $allowed_columns)) {
                    echo json_encode(['success' => false, 'message' => 'ទិន្នន័យមិនត្រឹមត្រូវ។']);
                    exit();
                }

                try {
                    $sql = "UPDATE {$table} SET {$column} = ? WHERE id = ?";
                    if ($stmt = $mysqli->prepare($sql)) {
                        $stmt->bind_param("si", $value, $id);
                        $stmt->execute();
                        $stmt->close();
                        echo json_encode(['success' => true, 'message' => 'រក្សាទុកទិន្នន័យរួចរាល់!']);
                    } else {
                        echo json_encode(['success' => false, 'message' => 'Query Error']);
                    }
                } catch (Exception $e) {
                    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
                }
                exit();

            case 'create_leave_deo_row':
                header('Content-Type: application/json');
                $date = $_POST['date'] ?? date('Y-m-d');
                $store = $_POST['store'] ?? 'ks2';
                $table_map = [
                    'ks2' => 'ks2_new_staff',
                    'nr3' => 'nr3_new_staff',
                    '318' => 'store_318_new_staff'
                ];
                $table = $table_map[$store] ?? 'ks2_new_staff';

                try {
                    $sql = "INSERT INTO {$table} (name, role, note, reports_date, number) VALUES ('', '', '', ?, '')";
                    if ($stmt = $mysqli->prepare($sql)) {
                        $stmt->bind_param("s", $date);
                        $stmt->execute();
                        $newId = $mysqli->insert_id;
                        $stmt->close();
                        echo json_encode(['success' => true, 'new_id' => $newId]);
                    } else {
                        echo json_encode(['success' => false, 'message' => 'Query Error']);
                    }
                } catch (Exception $e) {
                    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
                }
                exit();

            case 'get_report_data_json':
                $date = $_POST['date'] ?? date('Y-m-d');
                $store = $_POST['store'] ?? 'ks2';

                $tables_map = [
                    'ks2' => ['main' => 'ks2_consolidated_staff', 'new' => 'ks2_new_staff'],
                    'nr3' => ['main' => 'nr3_consolidated_staff', 'new' => 'nr3_new_staff'],
                    '318' => ['main' => 'store_318_consolidated_staff', 'new' => 'store_318_new_staff']
                ];
                
                $main_t = $tables_map[$store]['main'] ?? 'ks2_consolidated_staff';
                $new_t = $tables_map[$store]['new'] ?? 'ks2_new_staff';

                $attendance_res = (object)[];
                $st1 = $mysqli->prepare("SELECT * FROM {$main_t} WHERE reports_date = ?");
                $st1->bind_param("s", $date);
                $st1->execute();
                $res1 = $st1->get_result();
                if ($row1 = $res1->fetch_assoc()) {
                    $attendance_res = $row1;
                }
                $st1->close();

                $staff_res = [];
                $st2 = $mysqli->prepare("SELECT * FROM {$new_t} WHERE reports_date = ? ORDER BY id ASC");
                $st2->bind_param("s", $date);
                $st2->execute();
                $res2 = $st2->get_result();
                while ($row2 = $res2->fetch_assoc()) {
                    $staff_res[] = $row2;
                }
                $st2->close();

                echo json_encode([
                    'success' => true,
                    'attendance' => $attendance_res,
                    'staff' => $staff_res
                ]);
                exit();

            case 'delete_leave_deo_ajax':
                header('Content-Type: application/json');
                $id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
                $store = $_POST['store'] ?? 'ks2';
                
                $table_map = [
                    'ks2' => 'ks2_new_staff',
                    'nr3' => 'nr3_new_staff',
                    '318' => 'store_318_new_staff'
                ];
                $table = $table_map[$store] ?? 'ks2_new_staff';

                if (!$id) {
                    echo json_encode(['success' => false, 'message' => 'Invalid ID']);
                    exit();
                }
                try {
                    $sql = "DELETE FROM {$table} WHERE id = ?";
                    if ($stmt = $mysqli->prepare($sql)) {
                        $stmt->bind_param("i", $id);
                        $stmt->execute();
                        $stmt->close();
                        echo json_encode(['success' => true]);
                    } else {
                        echo json_encode(['success' => false, 'message' => 'Query Error']);
                    }
                } catch (Exception $e) {
                    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
                }
                exit();

    }
    exit;
}

$store = $_GET['store'] ?? 'ks2';
$selected_date = $_GET['filter_date'] ?? date('Y-m-d');
?>
<!DOCTYPE html>
<html lang="km">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>របាយការណ៍វត្តមាន - <?=$store?></title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Kh+Battambang:wght@400;700&family=Hanuman:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Kh Battambang', 'Hanuman', sans-serif; background: #f0f2f5; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .btn { display: inline-block; font-weight: 400; text-align: center; white-space: nowrap; vertical-align: middle; user-select: none; border: 1px solid transparent; padding: .375rem .75rem; font-size: 1rem; line-height: 1.5; border-radius: .25rem; transition: color .15s ease-in-out,background-color .15s ease-in-out,border-color .15s ease-in-out,box-shadow .15s ease-in-out; text-decoration: none; cursor: pointer; }
        .btn-primary { color: #fff; background-color: #0d6efd; border-color: #0d6efd; }
    </style>
</head>
<body>
<div class="container">
<?php
// Database mapping
    $tables = [
        'ks2' => ['main' => 'ks2_consolidated_staff', 'new' => 'ks2_new_staff', 'label' => 'ផ្សារកួរស្រូវ២'],
        'nr3' => ['main' => 'nr3_consolidated_staff', 'new' => 'nr3_new_staff', 'label' => 'NR3'],
        '318' => ['main' => 'store_318_consolidated_staff', 'new' => 'store_318_new_staff', 'label' => 'ហាងទំនិញ ៣១៨']
    ];
    
    $store_info = $tables[$store];
    $main_table = $store_info['main'];
    $new_table = $store_info['new'];

    // Load configs based on store
    $department_configs = [];
    if ($store === 'ks2') {
        $department_configs = [
            'cosmetic' => ['label' => 'ហាងគ្រឿងក្រអូប', 'colspan' => 1],
            'stock' => ['label' => 'ផ្នែកស្តុក', 'colspan' => 1],
            'sales' => ['label' => 'ផ្នែកលក់', 'colspan' => 1],
            'cashier' => ['label' => 'ផ្នែកគិតលុយ', 'colspan' => 1],
            'delivery' => ['label' => 'ផ្នែកដឹកជញ្ជូន', 'colspan' => 1],
        ];
    } elseif ($store === 'nr3') {
        $department_configs = [
            'store'    => ['label' => 'បុគ្គលិក NR3', 'colspan' => 1],
            'intern'   => ['label' => 'បុគ្គលិកកម្មសិក្សា', 'colspan' => 1],
            'stock'    => ['label' => 'ផ្នែកស្តុក', 'colspan' => 1],
            'sales'    => ['label' => 'ផ្នែកលក់', 'colspan' => 1],
            'cashier'  => ['label' => 'ផ្នែកគិតលុយ', 'colspan' => 1],
        ];
    } elseif ($store === '318') {
        $department_configs = [
            'store'   => ['label' => 'បុគ្គលិកហាងទំនិញ៣១៨', 'colspan' => 1],
            'intern'  => ['label' => 'បុគ្គលិកកម្មករ', 'colspan' => 1],
            'stock'   => ['label' => 'ផ្នែកស្តុក', 'colspan' => 1],
            'sales'   => ['label' => 'ផ្នែកលក់', 'colspan' => 1],
            'cashier' => ['label' => 'ផ្នែកគិតលុយ', 'colspan' => 1],
        ];
    }

    // Load daily records
    $daily_record = null;
    $sql = "SELECT * FROM {$main_table} WHERE reports_date = ?";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("s", $selected_date);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($row = $res->fetch_assoc()) {
            $daily_record = $row;
        } else {
            $daily_record = ['reports_date' => $selected_date];
            // Initialize defaults
            if ($store === 'ks2') {
                foreach ($department_configs as $key => $config) {
                    $daily_record["{$key}_female_morning"] = 0; $daily_record["{$key}_male_morning"] = 0;
                    $daily_record["{$key}_female_evening"] = 0; $daily_record["{$key}_male_evening"] = 0;
                }
            } else {
                foreach ($department_configs as $key => $config) {
                    $daily_record["{$key}_female"] = 0; $daily_record["{$key}_male"] = 0;
                }
            }
        }
        $stmt->close();
    }

    // Load new staff records
    $new_staff_records = [];
    $sql = "SELECT * FROM {$new_table} WHERE reports_date = ? ORDER BY id ASC";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("s", $selected_date);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($row = $res->fetch_assoc()) {
            $new_staff_records[] = $row;
        }
        $stmt->close();
    }
?>
    <style>
        .editable { cursor: pointer; transition: background-color 0.2s; min-width: 60px; height: 35px; text-align: center; vertical-align: middle; }
        .editable.editable-note { text-align: left; }
        .editable:hover { background-color: #f8f9fa; }
        .editable.editing { padding: 0 !important; }
        .editable input, .editable textarea {
            width: 100%; height: 100%; min-height: 35px; border: 2px solid #007bff; border-radius: 4px;
            padding: 4px 8px; box-sizing: border-box; font-family: inherit; resize: vertical; box-shadow: 0 0 5px rgba(0,123,255,0.3);
            text-align: center;
        }
        .editable-note input, .editable-note textarea { text-align: left; }
        .editable input:focus, .editable textarea:focus { outline: none; }
        
        .add-row-button-footer {
            background-color: #0d6efd; color: white; border: none; padding: 8px 16px;
            border-radius: 4px; cursor: pointer; font-size: 14px; font-weight: 500;
        }
        .add-row-button-footer:hover { background-color: #0b5ed7; }
        
        /* Table Styles from screenshot */
        .report-table { width: 100%; border-collapse: collapse; margin-bottom: 30px; border: 1px solid #dee2e6; font-family: 'Kh Battambang', 'Hanuman', serif; }
        .report-table th, .report-table td { border: 1px solid #dee2e6; padding: 12px; vertical-align: middle; font-size: 14px; }
        .report-table thead th { background-color: #05165e; color: white; text-align: center; font-weight: bold; border-color: #0d288a; }
        .report-table tbody th { background-color: #f8f9fa; text-align: center; font-weight: bold; }
        .total-row { background-color: #f1f3f5 !important; font-weight: bold; }
        
        .filter-panel { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 15px; margin-bottom: 25px; display: flex; align-items: center; justify-content: center; gap: 15px; }
        .filter-panel label { font-weight: bold; font-family: 'Kh Battambang', serif; margin: 0; }
        .filter-panel input[type="date"] { padding: 6px 12px; border: 1px solid #ced4da; border-radius: 4px; }
        .filter-panel button.screenshot-btn { background-color: #fd7e14; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: 500; }
        .filter-panel button.screenshot-btn:hover { background-color: #e86e04; }

        .report-title-container { text-align: center; margin-bottom: 25px; font-family: 'Kh Battambang', serif; color: #05165e; }
        .report-title-container h1 { font-size: 24px; font-weight: bold; margin-bottom: 5px; }
        .report-title-container h2 { font-size: 16px; font-weight: normal; margin-bottom: 15px; }
        .report-title-container h3 { font-size: 18px; font-weight: bold; margin-bottom: 0px; }
        
        .report-subtitle { text-align: center; font-size: 18px; font-weight: bold; font-family: 'Kh Battambang', serif; margin-bottom: 15px; }

        #toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 9999; }
        .toast {
            background-color: #fff; border-left: 5px solid #28a745; box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            padding: 15px 20px; margin-top: 10px; border-radius: 4px; display: none; opacity: 0;
            transition: opacity 0.3s;
        }
        .toast.show { display: block; opacity: 1; }
        .toast-error { border-left-color: #dc3545; }
        .hide-for-screenshot .actions-column { display: none; }
        .hide-for-screenshot .filter-panel { display: none; }
        .hide-for-screenshot .table-footer-actions { display: none; }
    </style>

    <?php
        function toKhmerNumber($number) {
            $khmerDigits = ['០', '១', '២', '៣', '៤', '៥', '៦', '៧', '៨', '៩'];
            return str_replace(range(0, 9), $khmerDigits, $number);
        }
        $date_obj = new DateTime($selected_date);
        $khmer_days = ['អាទិត្យ', 'ច័ន្ទ', 'អង្គារ', 'ពុធ', 'ព្រហស្បតិ៍', 'សុក្រ', 'សៅរ៍'];
        $khmer_months = ['មករា', 'កុម្ភៈ', 'មីនា', 'មេសា', 'ឧសភា', 'មិថុនា', 'កក្កដា', 'សីហា', 'កញ្ញា', 'តុលា', 'វិច្ឆិកា', 'ធ្នូ'];
        $weekday_index = (int) $date_obj->format('w');
        $day = toKhmerNumber($date_obj->format('d'));
        $month_index = (int) $date_obj->format('m') - 1;
        $year = toKhmerNumber($date_obj->format('Y'));
        $khmer_date_string = "ថ្ងៃ " . $khmer_days[$weekday_index] . " ទី" . $day . " ខែ" . $khmer_months[$month_index] . " ឆ្នាំ " . $year;
    ?>

    <div id="toast-container"></div>
    
    

    <div class="filter-panel" id="filterPanel">
        <form method="GET" action="public_report.php" style="display: flex; gap: 15px; align-items: center; margin: 0; flex-grow: 1;">
            
            
            <input type="hidden" name="store" value="<?= $store ?>">
            <label>មើលតាមថ្ងៃ៖</label>
            <input type="date" name="filter_date" value="<?php echo $selected_date; ?>" onchange="this.form.submit()">
        </form>
        <div style="display: flex; gap: 10px;">
            <button type="button" class="screenshot-btn" id="screenshotBtn"><i class="fas fa-camera"></i> ថតរូបតារាង</button>
            
        </div>
    </div>

    <div id="capture-area" style="background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow-x: auto;">
        
        <div class="report-title-container">
            <h1>របាយការណ៍វត្តមានបុគ្គលិក - <?= $store_info['label'] ?></h1>
            <h2><?= $khmer_date_string ?></h2>
            <h3>ចំនួនបុគ្គលិកតាមផ្នែក</h3>
        </div>

        <table class="report-table" id="attendance-table">
            <thead>
                <tr>
                    <th <?php echo ($store === 'ks2') ? 'colspan="2"' : ''; ?>>ព័ត៌មាន</th>
                    <?php foreach ($department_configs as $config): ?>
                        <th colspan="<?= $config['colspan'] ?? 1 ?>"><?= htmlspecialchars($config['label']) ?></th>
                    <?php endforeach; ?>
                    <th>សរុបរួម</th>
                </tr>
            </thead>
            <tbody>
                <?php if ($store === 'ks2'): 
                    // Specialty logic for KS2 shifts
                ?>
                    <tr>
                        <th rowspan="3" style="width: 80px;">វេនព្រឹក</th>
                        <th style="width: 80px;">ស្រី</th>
                        <?php foreach ($department_configs as $key => $config): ?>
                            <td class="editable" data-column="<?= $key ?>_female_morning" data-type="attendance"><?= $daily_record["{$key}_female_morning"] ?? 0 ?></td>
                        <?php endforeach; ?>
                        <td id="morning_female_total" style="font-weight: bold; text-align: center;">0</td>
                    </tr>
                    <tr>
                        <th style="width: 80px;">ប្រុស</th>
                        <?php foreach ($department_configs as $key => $config): ?>
                            <td class="editable" data-column="<?= $key ?>_male_morning" data-type="attendance"><?= $daily_record["{$key}_male_morning"] ?? 0 ?></td>
                        <?php endforeach; ?>
                        <td id="morning_male_total" style="font-weight: bold; text-align: center;">0</td>
                    </tr>
                    <tr class="total-row">
                        <td style="text-align: center; font-weight: bold;">សរុប (ព្រឹក)</td>
                        <?php foreach ($department_configs as $key => $config): ?>
                            <td data-total-column-morning="<?= $key ?>" style="text-align: center; font-weight: bold;">0</td>
                        <?php endforeach; ?>
                        <td id="morning_grand_total" style="text-align: center; font-weight: bold;">0</td>
                    </tr>
                    <tr>
                        <th rowspan="3" style="width: 80px;">វេនល្ងាច</th>
                        <th style="width: 80px;">ស្រី</th>
                        <?php foreach ($department_configs as $key => $config): ?>
                            <td class="editable" data-column="<?= $key ?>_female_evening" data-type="attendance"><?= $daily_record["{$key}_female_evening"] ?? 0 ?></td>
                        <?php endforeach; ?>
                        <td id="evening_female_total" style="font-weight: bold; text-align: center;">0</td>
                    </tr>
                    <tr>
                        <th style="width: 80px;">ប្រុស</th>
                        <?php foreach ($department_configs as $key => $config): ?>
                            <td class="editable" data-column="<?= $key ?>_male_evening" data-type="attendance"><?= $daily_record["{$key}_male_evening"] ?? 0 ?></td>
                        <?php endforeach; ?>
                        <td id="evening_male_total" style="font-weight: bold; text-align: center;">0</td>
                    </tr>
                    <tr class="total-row">
                        <td style="text-align: center; font-weight: bold;">សរុប (ល្ងាច)</td>
                        <?php foreach ($department_configs as $key => $config): ?>
                            <td data-total-column-evening="<?= $key ?>" style="text-align: center; font-weight: bold;">0</td>
                        <?php endforeach; ?>
                        <td id="evening_grand_total" style="text-align: center; font-weight: bold;">0</td>
                    </tr>
                <?php else: 
                    // Standard logic for NR3 and 318
                    $column_totals = array_fill_keys(array_keys($department_configs), 0);
                ?>
                    <tr>
                        <th style="width: 120px;">ស្រី</th>
                        <?php 
                        $row_total = 0; 
                        foreach ($department_configs as $key => $config): 
                            $val = $daily_record["{$key}_female"] ?? 0;
                            // Exclude 'store' key from row total logic based on user source code pattern
                            if ($key !== 'store') { $row_total += $val; }
                            $column_totals[$key] += $val; 
                        ?>
                            <td class="editable" data-column="<?= $key ?>_female" data-type="attendance"><?= $val ?></td>
                        <?php endforeach; ?>
                        <td id="female_row_total" style="font-weight: bold; text-align: center;"><?= $row_total ?></td>
                    </tr>
                    <tr>
                        <th style="width: 120px;">ប្រុស</th>
                        <?php 
                        $row_total = 0; 
                        foreach ($department_configs as $key => $config): 
                            $val = $daily_record["{$key}_male"] ?? 0;
                            if ($key !== 'store') { $row_total += $val; }
                            $column_totals[$key] += $val; 
                        ?>
                            <td class="editable" data-column="<?= $key ?>_male" data-type="attendance"><?= $val ?></td>
                        <?php endforeach; ?>
                        <td id="male_row_total" style="font-weight: bold; text-align: center;"><?= $row_total ?></td>
                    </tr>
                <?php endif; ?>
            </tbody>
            <?php if ($store === 'ks2'): ?>
                <tfoot>
                    <tr class="total-row">
                        <th colspan="2" style="background:#f1f3f5; color: black; border-color:#dee2e6;">សរុបរួមតាមផ្នែក</th>
                        <?php foreach ($department_configs as $key => $config): ?>
                            <td data-grand-total-column="<?= $key ?>" style="text-align: center;">0</td>
                        <?php endforeach; ?>
                        <td id="final_grand_total" style="text-align: center;">0</td>
                    </tr>
                </tfoot>
            <?php else: ?>
                <tfoot>
                    <tr class="total-row">
                        <th style="background:#f1f3f5; color: black; border-color:#dee2e6;">សរុបរួមតាមផ្នែក</th>
                        <?php 
                        $grand_total = 0; 
                        foreach ($column_totals as $key => $total): 
                            if ($key !== 'store') { $grand_total += $total; }
                        ?>
                            <td data-total-column="<?= $key ?>" style="text-align: center;"><?= $total ?></td>
                        <?php endforeach; ?>
                        <td id="grand_total" style="text-align: center;"><?= $grand_total ?></td>
                    </tr>
                </tfoot>
            <?php endif; ?>
        </table>

        <div class="report-subtitle">បុគ្គលិកសុំច្បាប់, ដេអូស, ប្តូរដេអូស និងចូលថ្មី</div>
        
        <table class="report-table" id="new-staff-table">
            <thead>
                <tr>
                    <th style="width: 60px;">ល.រ</th>
                    <th style="width: 20%;">ឈ្មោះ</th>
                    <th style="width: 15%;">តួនាទី</th>
                    <th style="width: 35%;">អធិប្បាយ</th>
                    <th style="width: 15%;">ថ្ងៃរាយការណ៍</th>
                    <th class="actions-column" style="width: 80px;">សកម្មភាព</th>
                </tr>
            </thead>
            <tbody>
                <?php if (!empty($new_staff_records)):
                    foreach ($new_staff_records as $row): ?>
                        <tr data-id="<?= $row['id'] ?>">
                            <td class="editable" data-column="number" data-type="staff"><?= htmlspecialchars($row['number']) ?></td>
                            <td class="editable editable-note" data-column="name" data-type="staff"><?= htmlspecialchars($row['name']) ?></td>
                            <td class="editable editable-note" data-column="role" data-type="staff"><?= htmlspecialchars($row['role']) ?></td>
                            <td class="editable editable-note" data-column="note" data-type="staff" style="white-space: pre-wrap;"><?= htmlspecialchars($row['note']) ?></td>
                            <td class="editable" data-column="reports_date" data-type="staff"><?= htmlspecialchars($row['reports_date']) ?></td>
                            <td class="actions-column" style="text-align: center;">
                                <button type="button" class="btn delete-btn" style="background: #dc3545; color: white; padding: 4px 10px; border: none; border-radius: 4px; pointer-events: auto;">លុប</button>
                            </td>
                        </tr>
                    <?php endforeach; else: ?>
                    <tr class="no-data-row">
                        <td colspan="6" style="text-align: center; color: #6c757d; padding: 20px;">មិនមានទិន្នន័យសម្រាប់ថ្ងៃនេះទេ ។</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
        
        <div class="table-footer-actions" style="display: flex; justify-content: center; gap: 10px; margin-top: 15px;">
            <button type="button" id="addNewRowBtn" class="add-row-button-footer">
                <i class="fas fa-plus"></i> បន្ថែមជួរដេកថ្មី
            </button>
        </div>
        
    </div>

    <!-- Modal for Screenshot -->
    <div id="screenshotModal" class="modal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:10000; flex-direction: column; align-items:center; justify-content:center;">
        <div class="modal-content" style="background:white; padding:20px; border-radius:8px; width:90%; max-width:1100px; max-height:90vh; overflow-y:auto; position:relative;">
            <div style="display:flex; justify-content:space-between; margin-bottom:15px; border-bottom: 1px solid #eee; padding-bottom: 15px;">
                <h3 style="margin:0;"><i class="fas fa-image" style="color:#007bff; margin-right:8px;"></i> រូបភាពតារាងទិន្នន័យ</h3>
                <button type="button" onclick="document.getElementById('screenshotModal').style.display='none'" style="background:none; border:none; font-size:24px; cursor:pointer;">&times;</button>
            </div>
            <div id="spinner-container" style="display:none; text-align:center; padding:40px;">កំពុងបង្កើតរូបភាព...</div>
            <div style="text-align:center; overflow:auto;"><img id="screenshotPreview" src="" alt="Screenshot" style="max-width:100%; display:none; border:1px solid #ddd; border-radius: 4px;"></div>
            <div style="margin-top:20px; text-align:right;">
                <button type="button" class="btn" style="background: #6c757d; color: white; padding: 8px 16px; border: none; border-radius: 4px; border: 1px solid #ccc;" onclick="document.getElementById('screenshotModal').style.display='none'">បិទ</button>
                <button type="button" class="btn btn-primary" id="copyImageBtn" style="margin-left: 10px; padding: 8px 16px; border: none; border-radius: 4px; background: #0d6efd; color: white;"><i class="fa-solid fa-copy"></i> ចម្លងរូបភាព</button>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <script>
        const storeId = '<?= $store ?>';
        const selectedDate = '<?= htmlspecialchars($selected_date) ?>';
        let activeInput = null;

        function showToast(message, type = 'success') {
            const container = document.getElementById('toast-container');
            if(!container) return alert(message);
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.textContent = message;
            container.appendChild(toast);
            setTimeout(() => { toast.classList.add('show'); }, 10);
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => { container.removeChild(toast); }, 300);
            }, 3000);
        }

        function calculateTotals() {
            const isKS2 = storeId === 'ks2';
            if (isKS2) {
                const depKeys = <?= json_encode(array_keys($department_configs)) ?>;
                ['morning', 'evening'].forEach(shift => {
                    let femaleShiftTotal = 0;
                    let maleShiftTotal = 0;
                    let shiftGrandTotal = 0;
                    
                    depKeys.forEach(key => {
                        const femaleCell = document.querySelector(`td[data-column="${key}_female_${shift}"]`);
                        const maleCell = document.querySelector(`td[data-column="${key}_male_${shift}"]`);
                        const fVal = femaleCell ? parseInt(femaleCell.textContent) || 0 : 0;
                        const mVal = maleCell ? parseInt(maleCell.textContent) || 0 : 0;
                        const colTotal = fVal + mVal;
                        
                        femaleShiftTotal += fVal;
                        maleShiftTotal += mVal;
                        shiftGrandTotal += colTotal;
                        
                        const colTotalCell = document.querySelector(`td[data-total-column-${shift}="${key}"]`);
                        if (colTotalCell) colTotalCell.textContent = colTotal;
                    });
                    
                    const fShiftCell = document.getElementById(`${shift}_female_total`);
                    if(fShiftCell) fShiftCell.textContent = femaleShiftTotal;
                    
                    const mShiftCell = document.getElementById(`${shift}_male_total`);
                    if(mShiftCell) mShiftCell.textContent = maleShiftTotal;
                    
                    const gShiftCell = document.getElementById(`${shift}_grand_total`);
                    if(gShiftCell) gShiftCell.textContent = shiftGrandTotal;
                });
                
                // Final Grand Total
                let finalGrandTotal = 0;
                depKeys.forEach(key => {
                    const mTotal = parseInt(document.querySelector(`td[data-total-column-morning="${key}"]`)?.textContent || 0);
                    const eTotal = parseInt(document.querySelector(`td[data-total-column-evening="${key}"]`)?.textContent || 0);
                    const dtTotal = mTotal + eTotal;
                    finalGrandTotal += dtTotal;
                    const gtCell = document.querySelector(`td[data-grand-total-column="${key}"]`);
                    if (gtCell) gtCell.textContent = dtTotal;
                });
                const fgtCell = document.getElementById('final_grand_total');
                if(fgtCell) fgtCell.textContent = finalGrandTotal;
                
            } else {
                const depKeys = <?= json_encode(array_keys($department_configs)) ?>;
                let femaleRowTotal = 0;
                let maleRowTotal = 0;
                let grandTotal = 0;

                depKeys.forEach(key => {
                    const femaleCell = document.querySelector(`td[data-column="${key}_female"]`);
                    const maleCell = document.querySelector(`td[data-column="${key}_male"]`);
                    const fVal = femaleCell ? parseInt(femaleCell.textContent) || 0 : 0;
                    const mVal = maleCell ? parseInt(maleCell.textContent) || 0 : 0;
                    const colTotal = fVal + mVal;
                    
                    if (key !== 'store') {
                        femaleRowTotal += fVal;
                        maleRowTotal += mVal;
                        grandTotal += colTotal;
                    }
                    
                    const footerCell = document.querySelector(`td[data-total-column="${key}"]`);
                    if (footerCell) {
                        footerCell.textContent = colTotal;
                    }
                });

                const fTot = document.getElementById('female_row_total');
                if (fTot) fTot.textContent = femaleRowTotal;
                const mTot = document.getElementById('male_row_total');
                if (mTot) mTot.textContent = maleRowTotal;
                const gtTot = document.getElementById('grand_total');
                if (gtTot) gtTot.textContent = grandTotal;
            }
        }
        
        // Initial calculation
        document.addEventListener('DOMContentLoaded', calculateTotals);

        async function saveData(action, data) {
            const formData = new FormData();
            formData.append('ajax_action', action);
            formData.append('store', storeId);
            for (const key in data) { formData.append(key, data[key]); }
            try {
                const response = await fetch('public_report.php', { method: 'POST', body: formData });
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                const result = await response.json();
                if (result.success) {
                    showToast(result.message || 'ជោគជ័យ!');
                    return result;
                } else {
                    showToast(result.message || 'មានបញ្ហា!', 'error');
                    return null;
                }
            } catch (error) {
                console.error(error);
                showToast('បរាជ័យក្នុងការតភ្ជាប់ទៅ Server', 'error');
                return null;
            }
        }

        document.getElementById('addNewRowBtn').addEventListener('click', async () => {
            const tableBody = document.querySelector('#new-staff-table tbody');
            const result = await saveData('create_leave_deo_row', { date: selectedDate });
            if (result && result.success && result.new_id) {
                const newId = result.new_id;
                const noDataRow = tableBody.querySelector('.no-data-row');
                if (noDataRow) noDataRow.remove();

                const newRow = document.createElement('tr');
                newRow.dataset.id = newId;
                newRow.innerHTML = `
            <td class="editable" data-column="number" data-type="staff" style="text-align: center;"></td>
            <td class="editable editable-note" data-column="name" data-type="staff"></td>
            <td class="editable editable-note" data-column="role" data-type="staff"></td>
            <td class="editable editable-note" data-column="note" data-type="staff" style="white-space: pre-wrap;"></td>
            <td class="editable" data-column="reports_date" data-type="staff" style="text-align: center;">${selectedDate}</td>
            <td class="actions-column" style="text-align: center;">
                <button type="button" class="btn delete-btn" style="background: #dc3545; color: white; padding: 4px 10px; border: none; border-radius: 4px; pointer-events: auto;">លុប</button>
            </td>`;
                tableBody.appendChild(newRow);
                showToast('បានបន្ថែមជួរដេកថ្មី!');
                const firstCell = newRow.querySelector('td.editable[data-column="number"]');
                if (firstCell) makeCellEditable(firstCell);
            }
        });

        function revertCell(cell, originalValue) {
            cell.classList.remove('editing');
            cell.innerHTML = originalValue;
        }

        function makeCellEditable(cell) {
            if (cell.classList.contains('editing')) return;
            const originalValue = cell.textContent.trim();
            const column = cell.dataset.column;
            const dataType = cell.dataset.type; // 'attendance' or 'staff'
            cell.classList.add('editing');

            let inputElement;
            if (column === 'note') {
                inputElement = document.createElement('textarea');
                inputElement.rows = 2;
            } else if (column === 'reports_date') {
                inputElement = document.createElement('input');
                inputElement.type = 'date';
            } else if (dataType === 'attendance') {
                inputElement = document.createElement('input');
                inputElement.type = 'number';
                inputElement.min = 0;
            } else {
                inputElement = document.createElement('input');
                inputElement.type = 'text';
            }
            
            inputElement.value = originalValue;
            cell.innerHTML = '';
            cell.appendChild(inputElement);
            inputElement.focus();
            if (dataType === 'attendance') inputElement.select(); // auto select numbers
            activeInput = inputElement;

            const saveAndRevert = async () => {
                const newValue = inputElement.value.trim();
                if (newValue !== originalValue) {
                    if (dataType === 'attendance') {
                        const numericVal = parseInt(newValue) || 0;
                        let data = { date: selectedDate, column: column, value: numericVal };
                        let result = await saveData('update_single_attendance', data);
                        revertCell(cell, result ? numericVal : originalValue);
                        if (result) calculateTotals();
                    } else {
                        let data = { column: column, value: newValue, id: cell.parentElement.dataset.id };
                        let result = await saveData('update_leave_deo_inline', data);
                        revertCell(cell, result ? newValue : originalValue);
                    }
                } else {
                    revertCell(cell, originalValue);
                }
                activeInput = null;
            };

            inputElement.addEventListener('blur', saveAndRevert);
            inputElement.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && (column !== 'note' || e.ctrlKey)) { e.preventDefault(); inputElement.blur(); }
                else if (e.key === 'Escape') {
                    inputElement.removeEventListener('blur', saveAndRevert);
                    revertCell(cell, originalValue); activeInput = null;
                }
            });
        }

        document.addEventListener('click', async (e) => {
            const editableCell = e.target.closest('td.editable');
            if (editableCell) {
                if (activeInput && !editableCell.contains(activeInput)) activeInput.blur();
                setTimeout(() => makeCellEditable(editableCell), 10);
            }
            
            const deleteBtn = e.target.closest('.delete-btn');
            if (deleteBtn) {
                e.preventDefault();
                if (!confirm('តើអ្នកប្រាកដជាចង់លុបមែនទេ?')) return;
                const row = deleteBtn.closest('tr');
                const id = row.dataset.id;
                const result = await saveData('delete_leave_deo_ajax', { id: id });
                if (result && result.success) {
                    row.remove();
                    const tb = document.querySelector('#new-staff-table tbody');
                    if(tb.children.length === 0) tb.innerHTML = '<tr class="no-data-row"><td colspan="6" style="text-align: center; color: #6c757d; padding: 20px;">មិនមានទិន្នន័យសម្រាប់ថ្ងៃនេះទេ ។</td></tr>';
                }
            }
        });

        // Screenshot
        const captureArea = document.getElementById('capture-area');
        let imageBlob = null;
        document.getElementById('screenshotBtn').addEventListener('click', async () => {
            const modal = document.getElementById('screenshotModal');
            const preview = document.getElementById('screenshotPreview');
            const spinner = document.getElementById('spinner-container');
            modal.style.display = 'flex';
            preview.style.display = 'none';
            spinner.style.display = 'block';
            captureArea.classList.add('hide-for-screenshot');
            try {
                const canvas = await html2canvas(captureArea, { scale: 2, backgroundColor: '#f4f7f9' });
                preview.src = canvas.toDataURL('image/png');
                preview.style.display = 'block';
                canvas.toBlob(blob => { imageBlob = blob; });
            } catch (error) {
                showToast('មានបញ្ហាក្នុងការបង្កើតរូបភាព', 'error');
            } finally {
                captureArea.classList.remove('hide-for-screenshot');
                spinner.style.display = 'none';
            }
        });

        document.getElementById('copyImageBtn').addEventListener('click', async () => {
            if (!imageBlob) return showToast('មិនមានរូបភាពសម្រាប់ចម្លងទេ', 'error');
            try {
                await navigator.clipboard.write([new ClipboardItem({'image/png': imageBlob})]);
                showToast('បានចម្លងរូបភាពដោយជោគជ័យ!');
            } catch (error) {
                showToast('បរាជ័យក្នុងការចម្លងរូបភាព', 'error');
            }
        });
    </script>

</div>
</body>
</html>
