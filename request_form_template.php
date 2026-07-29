<?php
// Request Form Template with Checkbox System
// This template provides a structured request form with checkbox selection for request types
// Supports A5 paper printing and mobile responsive design

if (!headers_sent()) {
    header('Content-Type: text/html; charset=UTF-8');
}
ini_set('default_charset', 'UTF-8');
mb_internal_encoding('UTF-8');

session_start();
require_once __DIR__ . '/config.php';

// Check authentication
if (!isset($_SESSION['admin_id'])) {
    header('Location: admin_attendance.php?page=login');
    exit;
}

// Get current user info
$current_admin_id = $_SESSION['admin_id'] ?? ($_SESSION['sub_user_parent_id'] ?? ($_SESSION['sub_user_id'] ?? 'SYSTEM_WIDE'));
$is_super_admin = !empty($_SESSION['is_super_admin']);

// Page title
$page_title = 'សំណើសុំសេវា - Request Form';
?>
<!DOCTYPE html>
<html lang="km">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Koulen&family=Battambang:wght@100;300;400;700;900&family=Kantumruy+Pro:ital,wght@0,100..700;1,100..700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/form_print.css">
    <style>
        body {
            font-family: 'Battambang', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
            margin: 0;
            padding: 20px;
        }
        
        .page-wrapper {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .no-print {
            margin-bottom: 20px;
        }
        
        .no-print button {
            background: white;
            color: var(--primary);
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-family: 'Battambang', sans-serif;
            font-size: 14px;
            margin-right: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .no-print button:hover {
            background: #f0f4ff;
        }
        
        .no-print button.print-btn {
            background: var(--success);
            color: white;
        }
        
        .no-print button.print-btn:hover {
            background: #15803d;
        }
    </style>
</head>
<body>
    <div class="page-wrapper">
        <!-- Control Buttons (No Print) -->
        <div class="no-print">
            <button onclick="window.print()" class="print-btn">
                <i class="fa-solid fa-print"></i> បោះពុម្ព (Print)
            </button>
            <button onclick="window.history.back()">
                <i class="fa-solid fa-arrow-left"></i> ត្រឡប់ក្រោយ (Back)
            </button>
        </div>
        
        <!-- Form Container -->
        <div class="form-container">
            <!-- Form Header -->
            <div class="form-header">
                <h1>សំណើសុំសេវា</h1>
                <h2>SERVICE REQUEST FORM</h2>
            </div>
            
            <!-- Request Type Selection with Checkboxes -->
            <div class="form-section">
                <div class="form-section-title">
                    <i class="fa-solid fa-list-check"></i> ប្រភេទសំណើ (Request Type)
                </div>
                
                <div class="request-type-checkboxes">
                    <label class="request-type-checkbox request-type-leave">
                        <input type="checkbox" name="request_type" value="leave" id="req-leave">
                        <span class="request-type-icon"></span>
                        <span>ច្បាប់ (Leave)</span>
                    </label>
                    
                    <label class="request-type-checkbox request-type-late">
                        <input type="checkbox" name="request_type" value="late" id="req-late">
                        <span class="request-type-icon"></span>
                        <span>មកយឺត (Late)</span>
                    </label>
                    
                    <label class="request-type-checkbox request-type-forgotten">
                        <input type="checkbox" name="request_type" value="forgotten_scan" id="req-forgotten">
                        <span class="request-type-icon"></span>
                        <span>ភ្លេចស្កេន (Forgotten Scan)</span>
                    </label>
                    
                    <label class="request-type-checkbox request-type-deo">
                        <input type="checkbox" name="request_type" value="deo" id="req-deo">
                        <span class="request-type-icon"></span>
                        <span>ដេអូស (DEO)</span>
                    </label>
                </div>
            </div>
            
            <!-- Employee Information -->
            <div class="form-section">
                <div class="form-section-title">
                    <i class="fa-solid fa-user"></i> ព័ត៌មានបុគ្គលិក (Employee Information)
                </div>
                
                <div class="form-row">
                    <div class="form-field half">
                        <label class="form-label">ឈ្មោះ (Name)</label>
                        <div class="form-value" id="employee-name">_____________________</div>
                    </div>
                    
                    <div class="form-field half">
                        <label class="form-label">លេខសម្គាល់ (Employee ID)</label>
                        <div class="form-value" id="employee-id">_____________________</div>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-field half">
                        <label class="form-label">ផ្នែក (Department)</label>
                        <div class="form-value" id="department">_____________________</div>
                    </div>
                    
                    <div class="form-field half">
                        <label class="form-label">មុខតំណែង (Position)</label>
                        <div class="form-value" id="position">_____________________</div>
                    </div>
                </div>
            </div>
            
            <!-- Request Details -->
            <div class="form-section">
                <div class="form-section-title">
                    <i class="fa-solid fa-calendar"></i> ព័ត៌មានសំណើ (Request Details)
                </div>
                
                <div class="form-row">
                    <div class="form-field half">
                        <label class="form-label">កាលបរិច្ឆេទស្នើ (Request Date)</label>
                        <div class="form-value" id="request-date">_____________________</div>
                    </div>
                    
                    <div class="form-field half">
                        <label class="form-label">ស្ថានភាព (Status)</label>
                        <div class="form-value">
                            <span class="status-badge status-pending">Pending</span>
                        </div>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-field">
                        <label class="form-label">មូលហេតុ (Reason)</label>
                        <div class="form-value" id="reason" style="min-height: 80px;">_______________________________________________________________________</div>
                    </div>
                </div>
            </div>
            
            <!-- Additional Notes -->
            <div class="form-section">
                <div class="form-section-title">
                    <i class="fa-solid fa-sticky-note"></i> កំណត់សម្គាល់ (Additional Notes)
                </div>
                
                <div class="form-row">
                    <div class="form-field">
                        <label class="form-label">មតិយោបល់ (Comments)</label>
                        <div class="form-value" id="comments" style="min-height: 60px;">_______________________________________________________________________</div>
                    </div>
                </div>
            </div>
            
            <!-- Approval Section -->
            <div class="form-section">
                <div class="form-section-title">
                    <i class="fa-solid fa-clipboard-check"></i> ការយល់ព្រម (Approval)
                </div>
                
                <div class="form-row">
                    <div class="form-field half">
                        <label class="form-label">អ្នកយល់ព្រម (Approved By)</label>
                        <div class="form-value" id="approved-by">_____________________</div>
                    </div>
                    
                    <div class="form-field half">
                        <label class="form-label">កាលបរិច្ឆេទយល់ព្រម (Approval Date)</label>
                        <div class="form-value" id="approval-date">_____________________</div>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-field">
                        <label class="form-label">មតិយោបល់របស់អ្នកគ្រប់គ្រង (Admin Comment)</label>
                        <div class="form-value" id="admin-comment" style="min-height: 60px;">_______________________________________________________________________</div>
                    </div>
                </div>
            </div>
            
            <!-- Signature Section -->
            <div class="form-footer">
                <div class="signature-box">
                    <div class="signature-label">ហត្ថលេខាបុគ្គលិក (Employee Signature)</div>
                    <div class="signature-line"></div>
                </div>
                
                <div class="signature-box">
                    <div class="signature-label">ហត្ថលេខាអ្នកគ្រប់គ្រង (Manager Signature)</div>
                    <div class="signature-line"></div>
                </div>
                
                <div class="signature-box">
                    <div class="signature-label">ហត្ថលេខាធនាគារ (HR Signature)</div>
                    <div class="signature-line"></div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Handle checkbox selection (only one at a time)
        document.querySelectorAll('input[name="request_type"]').forEach(checkbox => {
            checkbox.addEventListener('change', function() {
                if (this.checked) {
                    document.querySelectorAll('input[name="request_type"]').forEach(cb => {
                        if (cb !== this) {
                            cb.checked = false;
                            cb.closest('.request-type-checkbox').classList.remove('checked');
                        }
                    });
                    this.closest('.request-type-checkbox').classList.add('checked');
                } else {
                    this.closest('.request-type-checkbox').classList.remove('checked');
                }
            });
        });
        
        // Auto-fill current date
        document.addEventListener('DOMContentLoaded', function() {
            const today = new Date().toISOString().split('T')[0];
            const requestDateEl = document.getElementById('request-date');
            if (requestDateEl) {
                requestDateEl.textContent = today;
            }
        });
        
        // Print functionality
        function printForm() {
            window.print();
        }
    </script>
</body>
</html>