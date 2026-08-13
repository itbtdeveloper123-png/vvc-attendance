<?php
// Poll Management UI - Candidate Selection from Employee List
require_once 'config.php';

$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

// Get current action
$action = $_GET['action'] ?? 'manage_polls';
$poll_id = $_GET['id'] ?? 0;

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['save_poll'])) {
        // Save or update poll
        $title = $mysqli->real_escape_string($_POST['title']);
        $quarter = $mysqli->real_escape_string($_POST['quarter']);
        $location = $mysqli->real_escape_string($_POST['location']);
        $start_date = $mysqli->real_escape_string($_POST['start_date']);
        $end_date = $mysqli->real_escape_string($_POST['end_date']);
        $access_code = $mysqli->real_escape_string($_POST['access_code'] ?? '');
        $is_active = isset($_POST['is_active']) ? 1 : 0;
        
        // Handle allowed employees
        $allowed_employees = isset($_POST['allowed_employees']) ? json_encode($_POST['allowed_employees']) : '[]';
        
        // Handle excluded employees
        $excluded_employees = isset($_POST['excluded_employees']) ? json_encode($_POST['excluded_employees']) : '[]';
        
        if ($poll_id > 0) {
            // Update existing poll
            $update = "UPDATE poll_events SET title='$title', quarter='$quarter', location='$location', 
                      start_date='$start_date', end_date='$end_date', access_code='$access_code', 
                      is_active=$is_active, allowed_employee_ids='$allowed_employees', 
                      excluded_employee_ids='$excluded_employees' WHERE id=$poll_id";
            $mysqli->query($update);
        } else {
            // Create new poll
            $insert = "INSERT INTO poll_events (title, quarter, location, start_date, end_date, access_code, 
                       is_active, allowed_employee_ids, excluded_employee_ids) 
                       VALUES ('$title', '$quarter', '$location', '$start_date', '$end_date', 
                       '$access_code', $is_active, '$allowed_employees', '$excluded_employees')";
            $mysqli->query($insert);
            $poll_id = $mysqli->insert_id;
        }
        
        // Handle candidates using UPSERT so ON DELETE CASCADE does NOT delete poll_votes
        if (isset($_POST['candidates']) && is_array($_POST['candidates'])) {
            foreach ($_POST['candidates'] as $emp_id) {
                $category = $_POST['candidate_category'][$emp_id] ?? 'Head Office';
                $emp_id = $mysqli->real_escape_string(trim($emp_id));
                $category = $mysqli->real_escape_string(trim($category));
                if (!empty($emp_id)) {
                    $check = $mysqli->query("SELECT id FROM poll_candidates WHERE poll_id = $poll_id AND (employee_id = '$emp_id' OR LTRIM(employee_id, '0') = LTRIM('$emp_id', '0')) LIMIT 1");
                    if ($check && $c_row = $check->fetch_assoc()) {
                        $mysqli->query("UPDATE poll_candidates SET category = '$category' WHERE id = " . (int)$c_row['id']);
                    } else {
                        $mysqli->query("INSERT INTO poll_candidates (poll_id, employee_id, category) VALUES ($poll_id, '$emp_id', '$category')");
                    }
                }
            }
        }
        
        header("Location: ?page=polls&action=manage_polls");
        exit;
    }
    
    if (isset($_POST['delete_poll'])) {
        $delete_id = (int)$_POST['poll_id'];
        $mysqli->query("DELETE FROM poll_events WHERE id = $delete_id");
        header("Location: ?page=polls&action=manage_polls");
        exit;
    }
}

// Get poll data if editing
$poll_data = null;
$candidates = [];
if ($poll_id > 0) {
    $result = $mysqli->query("SELECT * FROM poll_events WHERE id = $poll_id");
    if ($result) {
        $poll_data = $result->fetch_assoc();
        
        // Get candidates for this poll
        $candidate_result = $mysqli->query("SELECT * FROM poll_candidates WHERE poll_id = $poll_id");
        if ($candidate_result) {
            while ($row = $candidate_result->fetch_assoc()) {
                $candidates[] = $row;
            }
        }
    }
}

// Get all active employees
$employees_result = $mysqli->query("SELECT employee_id, name, branch FROM users WHERE employment_status = 'Active' ORDER BY name ASC");
$employees = [];
if ($employees_result) {
    while ($row = $employees_result->fetch_assoc()) {
        $employees[] = $row;
    }
}

// Get all polls
$polls_result = $mysqli->query("SELECT * FROM poll_events ORDER BY created_at DESC");
$polls = [];
if ($polls_result) {
    while ($row = $polls_result->fetch_assoc()) {
        // Get candidate count for each poll
        $poll_id_check = $row['id'];
        $count_result = $mysqli->query("SELECT COUNT(*) as count FROM poll_candidates WHERE poll_id = $poll_id_check");
        $count_row = $count_result->fetch_assoc();
        $row['candidate_count'] = $count_row['count'];
        $polls[] = $row;
    }
}
?>

<!DOCTYPE html>
<html lang="km">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>គ្រប់គ្រងការបោះឆ្នោត</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            font-family: 'Kantumruy Pro', sans-serif;
            background: #f5f5f5;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #333;
        }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            text-decoration: none;
            display: inline-block;
        }
        .btn-primary {
            background: #4f46e5;
            color: white;
        }
        .btn-danger {
            background: #ef4444;
            color: white;
        }
        .btn-success {
            background: #10b981;
            color: white;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input, select, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #f8f9fa;
            font-weight: bold;
        }
        .status-active {
            color: #10b981;
            font-weight: bold;
        }
        .status-inactive {
            color: #ef4444;
            font-weight: bold;
        }
        .employee-checkbox {
            margin: 5px 0;
        }
        .candidate-section {
            background: #f9fafb;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
        .candidate-item {
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if ($action == 'manage_polls'): ?>
            <h1>គ្រប់គ្រងការបោះឆ្នោត</h1>
            <a href="?page=polls&action=create_poll" class="btn btn-primary">
                <i class="fas fa-plus"></i> បង្កើតការបោះឆ្នោតថ្មី
            </a>
            
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>ចំណងជើង</th>
                        <th>ត្រីមាស</th>
                        <th>ទីតាំង</th>
                        <th>កាលបរិច្ឆេទ</th>
                        <th>Candidates</th>
                        <th>ស្ថានភាព</th>
                        <th>សកម្មភាព</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($polls as $poll): ?>
                    <tr>
                        <td><?php echo $poll['id']; ?></td>
                        <td><?php echo htmlspecialchars($poll['title']); ?></td>
                        <td><?php 
                            $q_val = $poll['quarter'] ?? '-';
                            if ($q_val === 'Q1') $q_val = 'ត្រីមាសទី ១';
                            else if ($q_val === 'Q2') $q_val = 'ត្រីមាសទី ២';
                            else if ($q_val === 'Q3') $q_val = 'ត្រីមាសទី ៣';
                            else if ($q_val === 'Q4') $q_val = 'ត្រីមាសទី ៤';
                            echo htmlspecialchars($q_val);
                        ?></td>
                        <td><?php echo htmlspecialchars($poll['location'] ?? '-'); ?></td>
                        <td><?php echo $poll['start_date']; ?> ដល់ <?php echo $poll['end_date']; ?></td>
                        <td><?php echo $poll['candidate_count']; ?> នាក់</td>
                        <td>
                            <?php if ($poll['candidate_count'] > 0): ?>
                                <span class="status-active">មាន Candidates</span>
                            <?php else: ?>
                                <span class="status-inactive">គ្មាន Candidates</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($poll['is_active']): ?>
                                <span class="status-active">Active</span>
                            <?php else: ?>
                                <span class="status-inactive">Inactive</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <a href="?page=polls&action=create_poll&id=<?php echo $poll['id']; ?>" class="btn btn-primary">
                                <i class="fas fa-edit"></i>
                            </a>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="poll_id" value="<?php echo $poll['id']; ?>">
                                <button type="submit" name="delete_poll" class="btn btn-danger" onclick="return confirm('តើអ្នកប្រាកដជាចង់លុបចេញ?');">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
        <?php elseif ($action == 'create_poll'): ?>
            <h1><?php echo $poll_id > 0 ? 'កែប្រែការបោះឆ្នោត' : 'បង្កើតការបោះឆ្នោតថ្មី'; ?></h1>
            <a href="?page=polls&action=manage_polls" class="btn btn-primary">
                <i class="fas fa-arrow-left"></i> ត្រឡប់ក្រោយ
            </a>
            
            <form method="POST">
                <div class="form-group">
                    <label>ចំណងជើង *</label>
                    <input type="text" name="title" required value="<?php echo $poll_data['title'] ?? ''; ?>">
                </div>
                
                <div class="form-group">
                    <label>ត្រីមាស</label>
                    <select name="quarter">
                        <option value="">ជ្រើសរើសត្រីមាស</option>
                        <option value="ត្រីមាសទី ១" <?php echo in_array($poll_data['quarter'] ?? '', ['Q1', 'ត្រីមាសទី ១']) ? 'selected' : ''; ?>>ត្រីមាសទី ១</option>
                        <option value="ត្រីមាសទី ២" <?php echo in_array($poll_data['quarter'] ?? '', ['Q2', 'ត្រីមាសទី ២']) ? 'selected' : ''; ?>>ត្រីមាសទី ២</option>
                        <option value="ត្រីមាសទី ៣" <?php echo in_array($poll_data['quarter'] ?? '', ['Q3', 'ត្រីមាសទី ៣']) ? 'selected' : ''; ?>>ត្រីមាសទី ៣</option>
                        <option value="ត្រីមាសទី ៤" <?php echo in_array($poll_data['quarter'] ?? '', ['Q4', 'ត្រីមាសទី ៤']) ? 'selected' : ''; ?>>ត្រីមាសទី ៤</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>ទីតាំង/ឃ្លាំង</label>
                    <select name="location">
                        <option value="">ជ្រើសរើសទីតាំង/ឃ្លាំង</option>
                        <option value="ការិយាល័យកណ្តាល" <?php echo in_array($poll_data['location'] ?? '', ['Head Office', 'ការិយាល័យកណ្តាល']) ? 'selected' : ''; ?>>ការិយាល័យកណ្តាល</option>
                        <option value="ឃ្លាំង" <?php echo in_array($poll_data['location'] ?? '', ['Warehouse', 'Store 318', 'ឃ្លាំង']) ? 'selected' : ''; ?>>ឃ្លាំង</option>
                        <option value="ឃ្លាំង PRV" <?php echo in_array($poll_data['location'] ?? '', ['Warehouse PRV', 'ឃ្លាំង PRV']) ? 'selected' : ''; ?>>ឃ្លាំង PRV</option>
                        <option value="ឃ្លាំង PSP" <?php echo in_array($poll_data['location'] ?? '', ['Warehouse PSP', 'ឃ្លាំង PSP']) ? 'selected' : ''; ?>>ឃ្លាំង PSP</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>កាលបរិច្ឆេទចាប់ផ្តើម *</label>
                    <input type="date" name="start_date" required value="<?php echo $poll_data['start_date'] ?? ''; ?>">
                </div>
                
                <div class="form-group">
                    <label>កាលបរិច្ឆេទបញ្ចប់ *</label>
                    <input type="date" name="end_date" required value="<?php echo $poll_data['end_date'] ?? ''; ?>">
                </div>
                
                <div class="form-group">
                    <label>Access Code (ជម្រើស)</label>
                    <input type="text" name="access_code" value="<?php echo $poll_data['access_code'] ?? ''; ?>">
                </div>
                
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="is_active" <?php echo ($poll_data['is_active'] ?? 1) == 1 ? 'checked' : ''; ?>>
                        សកម្ម (Active)
                    </label>
                </div>
                
                <div class="candidate-section">
                    <h3>ជ្រើសរើសបុគ្គលិកដែលអាចបោះឆ្នោត</h3>
                    <div style="max-height: 200px; overflow-y: auto;">
                        <?php 
                        $allowed_ids = [];
                        if ($poll_data && !empty($poll_data['allowed_employee_ids'])) {
                            $raw_a = $poll_data['allowed_employee_ids'];
                            $dec_a = json_decode($raw_a, true);
                            if (is_string($dec_a)) $dec_a = json_decode($dec_a, true);
                            if (is_array($dec_a)) $allowed_ids = array_map('strval', $dec_a);
                        }
                        $clean_allowed_ids = array_map(function($id) { return ltrim((string)$id, '0'); }, $allowed_ids);
                        ?>
                        <?php foreach ($employees as $emp): 
                            $emp_str = (string)$emp['employee_id'];
                            $emp_clean = ltrim($emp_str, '0');
                            $is_checked = in_array($emp_str, $allowed_ids) || ($emp_clean !== '' && in_array($emp_clean, $clean_allowed_ids));
                        ?>
                            <div class="employee-checkbox">
                                <label>
                                    <input type="checkbox" name="allowed_employees[]" 
                                           value="<?php echo $emp['employee_id']; ?>"
                                           <?php echo $is_checked ? 'checked' : ''; ?>>
                                    <?php echo htmlspecialchars($emp['name']); ?> (<?php echo $emp['employee_id']; ?>)
                                </label>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                
                <div class="candidate-section">
                    <h3>ជ្រើសរើស Candidates (បេក្ខជនសម្រាប់បោះឆ្នោត)</h3>
                    <p style="color: #666; font-size: 14px;">ជ្រើសរើសបុគ្គលិកដែលអ្នកចង់ឱ្យគេបោះឆ្នោតឱ្យ</p>
                    <div style="max-height: 300px; overflow-y: auto;">
                        <?php 
                        $candidate_ids = [];
                        foreach ($candidates as $cand) {
                            $candidate_ids[$cand['employee_id']] = $cand['category'];
                        }
                        ?>
                        <?php foreach ($employees as $emp): ?>
                            <div class="candidate-item">
                                <input type="checkbox" name="candidates[]" 
                                       value="<?php echo $emp['employee_id']; ?>"
                                       <?php echo isset($candidate_ids[$emp['employee_id']]) ? 'checked' : ''; ?>>
                                <span><?php echo htmlspecialchars($emp['name']); ?> (<?php echo $emp['employee_id']; ?>)</span>
                                <select name="candidate_category[<?php echo $emp['employee_id']; ?>]" style="width: auto;">
                                    <option value="ការិយាល័យកណ្តាល" <?php echo in_array($candidate_ids[$emp['employee_id']] ?? '', ['Head Office', 'ការិយាល័យកណ្តាល']) ? 'selected' : ''; ?>>ការិយាល័យកណ្តាល</option>
                                    <option value="ឃ្លាំង" <?php echo in_array($candidate_ids[$emp['employee_id']] ?? '', ['Warehouse', 'Store 318', 'ឃ្លាំង']) ? 'selected' : ''; ?>>ឃ្លាំង</option>
                                    <option value="ឃ្លាំង PRV" <?php echo in_array($candidate_ids[$emp['employee_id']] ?? '', ['Warehouse PRV', 'ឃ្លាំង PRV']) ? 'selected' : ''; ?>>ឃ្លាំង PRV</option>
                                    <option value="ឃ្លាំង PSP" <?php echo in_array($candidate_ids[$emp['employee_id']] ?? '', ['Warehouse PSP', 'ឃ្លាំង PSP']) ? 'selected' : ''; ?>>ឃ្លាំង PSP</option>
                                </select>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                
                <button type="submit" name="save_poll" class="btn btn-success">
                    <i class="fas fa-save"></i> រក្សាទុក
                </button>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>