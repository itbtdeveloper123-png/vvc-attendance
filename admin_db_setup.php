<?php
date_default_timezone_set('Asia/Phnom_Penh');
error_log("DB_SETUP: admin_db_setup.php loaded");
/**
 * admin_db_setup.php
 * Handles initial database schema setup and migrations for the Admin Panel.
 * This file is required by admin_attendance.php to ensure all necessary columns and tables exist.
 */

/**
 * Ensure core tables (users, attendance, app_settings, etc.) have all basic columns.
 */
if (!function_exists('ensure_core_tables')) {
    function ensure_core_tables($mysqli) {
        // Basic app_settings table
        $mysqli->query("CREATE TABLE IF NOT EXISTS app_settings (
            admin_id VARCHAR(50) DEFAULT 'SYSTEM_WIDE',
            setting_key VARCHAR(100) NOT NULL,
            setting_value TEXT,
            PRIMARY KEY (admin_id, setting_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        // Basic user_form_fields table
        $mysqli->query("CREATE TABLE IF NOT EXISTS user_form_fields (
            id INT AUTO_INCREMENT PRIMARY KEY,
            field_key VARCHAR(50) UNIQUE,
            field_label VARCHAR(100),
            field_type VARCHAR(20) DEFAULT 'text',
            is_required TINYINT(1) DEFAULT 0,
            field_order INT DEFAULT 0,
            is_deletable TINYINT(1) DEFAULT 1
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
        
        // Ensure some basic columns in users table
        $mysqli->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS system_role VARCHAR(50) DEFAULT 'User'");
        $mysqli->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS access_mode VARCHAR(50) DEFAULT 'Normal'");
        $mysqli->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50) DEFAULT NULL");
        $mysqli->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified TINYINT(1) DEFAULT 0");
        // Fix any NULL values so toggle (0→1, 1→0) works correctly
        $mysqli->query("UPDATE users SET is_verified = 0 WHERE is_verified IS NULL");
    }
}

/**
 * Ensure employment status columns and logs table.
 */
if (!function_exists('ensure_employment_columns_and_logs')) {
    function ensure_employment_columns_and_logs($mysqli) {
        // Add columns to users table
        $mysqli->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS employment_status ENUM('Active', 'Inactive', 'Resigned') DEFAULT 'Active'");
        $mysqli->query("ALTER TABLE users ADD COLUMN IF NOT EXISTS leave_date DATE DEFAULT NULL");

        // Create user_employment_logs table
        $mysqli->query("CREATE TABLE IF NOT EXISTS user_employment_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_id VARCHAR(50) NOT NULL,
            status_from VARCHAR(50),
            status_to VARCHAR(50),
            updated_by VARCHAR(50),
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    }
}

/**
 * Ensure 'noted' column exists in attendance table.
 */
if (!function_exists('ensure_noted_column')) {
    function ensure_noted_column($mysqli) {
        $mysqli->query("ALTER TABLE attendance ADD COLUMN IF NOT EXISTS noted TEXT NULL");
    }
}

/**
 * Ensure user groups table exists.
 */
if (!function_exists('ensure_user_groups_table')) {
    function ensure_user_groups_table($mysqli) {
        $mysqli->query("CREATE TABLE IF NOT EXISTS user_skill_groups (
            id INT AUTO_INCREMENT PRIMARY KEY,
            group_name VARCHAR(100) NOT NULL,
            sort_order INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
        
        // Migration: add sort_order if missing
        $check = $mysqli->query("SHOW COLUMNS FROM user_skill_groups LIKE 'sort_order'");
        if ($check && $check->num_rows == 0) {
            $mysqli->query("ALTER TABLE user_skill_groups ADD COLUMN sort_order INT DEFAULT 0 AFTER group_name");
        }
    }
}

/**
 * Ensure sub-accounts table exists.
 */
if (!function_exists('ensure_user_subaccounts_table')) {
    function ensure_user_subaccounts_table($mysqli) {
        $mysqli->query("CREATE TABLE IF NOT EXISTS user_subaccounts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            parent_employee_id VARCHAR(50) NOT NULL,
            sub_id VARCHAR(50) UNIQUE NOT NULL,
            sub_name VARCHAR(255),
            password_hash VARCHAR(255),
            ui_permissions TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    }
}

/**
 * Ensure column visibility table exists.
 */
if (!function_exists('ensure_column_visibility_table')) {
    function ensure_column_visibility_table($mysqli) {
        $mysqli->query("CREATE TABLE IF NOT EXISTS column_visibility (
            admin_id VARCHAR(50) NOT NULL,
            page_key VARCHAR(50) NOT NULL,
            hidden_columns TEXT,
            PRIMARY KEY (admin_id, page_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    }
}

/**
 * Ensure push subscriptions table exists.
 */
if (!function_exists('ensure_push_subscriptions_table')) {
    function ensure_push_subscriptions_table($mysqli) {
        $mysqli->query("CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id VARCHAR(50) NOT NULL,
            endpoint TEXT NOT NULL,
            p256dh TEXT,
            auth TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    }
}

/**
 * Ensure workspace card order table exists.
 */
if (!function_exists('ensure_workspace_card_orders_table')) {
    function ensure_workspace_card_orders_table($mysqli) {
        $mysqli->query("CREATE TABLE IF NOT EXISTS workspace_card_orders (
            admin_id VARCHAR(50) NOT NULL,
            page_key VARCHAR(100) NOT NULL,
            sort_order INT NOT NULL DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (admin_id, page_key),
            KEY idx_admin_order (admin_id, sort_order)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    }
}

/**
 * Ensure meeting and agenda tables exist.
 */
if (!function_exists('ensure_meeting_tables')) {
    function ensure_meeting_tables($mysqli) {
        $mysqli->query("CREATE TABLE IF NOT EXISTS meetings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            meeting_date DATE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        $mysqli->query("CREATE TABLE IF NOT EXISTS meeting_agenda (
            id INT AUTO_INCREMENT PRIMARY KEY,
            meeting_id INT NOT NULL,
            agenda_item TEXT,
            is_completed TINYINT(1) DEFAULT 0
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    }
}

/**
 * Ensure notification tables exist.
 */
if (!function_exists('ensure_notification_tables')) {
    function ensure_notification_tables($mysqli) {
        $mysqli->query("CREATE TABLE IF NOT EXISTS notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            admin_id VARCHAR(64) NOT NULL,
            title VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            recipient_type ENUM('all', 'role', 'specific') DEFAULT 'all',
            recipient_info VARCHAR(255) DEFAULT NULL,
            expiry_date DATE DEFAULT NULL,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        $mysqli->query("CREATE TABLE IF NOT EXISTS user_notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            notification_id INT NOT NULL,
            employee_id VARCHAR(64) NOT NULL,
            is_read TINYINT(1) NOT NULL DEFAULT 0,
            read_at DATETIME DEFAULT NULL,
            KEY idx_notif_id (notification_id),
            KEY idx_emp_read (employee_id, is_read)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    }
}

/**
 * Process auto-resignation for users whose leave date has passed.
 */
if (!function_exists('auto_resign_due_users')) {
    function auto_resign_due_users($mysqli) {
        $today = date('Y-m-d');
        // Update users who are still 'Active' but whose leave_date is today or in the past
        $stmt = $mysqli->prepare("UPDATE users SET employment_status = 'Inactive' WHERE employment_status = 'Active' AND leave_date IS NOT NULL AND leave_date <= ?");
        if ($stmt) {
            $stmt->bind_param("s", $today);
            $stmt->execute();
            $stmt->close();
        }
    }
}

/**
 * Ensure user_fcm_tokens table exists (supports multiple devices per user).
 */
if (!function_exists('ensure_fcm_tokens_table')) {
    function ensure_fcm_tokens_table($mysqli) {
        $mysqli->query("CREATE TABLE IF NOT EXISTS user_fcm_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_id VARCHAR(64) NOT NULL,
            fcm_token VARCHAR(255) NOT NULL,
            platform VARCHAR(20) DEFAULT NULL,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_token (fcm_token),
            KEY idx_eid (employee_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    }
}

/**
 * Ensure payroll related tables exist.
 */
if (!function_exists('ensure_payroll_tables')) {
    function ensure_payroll_tables($mysqli) {
        // 1. Payroll Configuration (Base Salary etc. per user)
        $mysqli->query("CREATE TABLE IF NOT EXISTS payroll_configs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_id VARCHAR(50) UNIQUE NOT NULL,
            base_salary DECIMAL(15, 2) DEFAULT 0.00,
            currency VARCHAR(10) DEFAULT 'USD',
            payment_type ENUM('Monthly', 'Daily', 'Hourly') DEFAULT 'Monthly',
            bank_name VARCHAR(100) DEFAULT NULL,
            bank_account_number VARCHAR(100) DEFAULT NULL,
            tax_id VARCHAR(50) DEFAULT NULL,
            social_security_id VARCHAR(50) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_employee (employee_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        // 2. Salary Components (Allowances, Deductions, etc.)
        $mysqli->query("CREATE TABLE IF NOT EXISTS payroll_components (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_id VARCHAR(50) NOT NULL,
            component_name VARCHAR(100) NOT NULL,
            component_type ENUM('Allowance', 'Deduction', 'Bonus', 'Overtime') NOT NULL,
            amount DECIMAL(15, 2) DEFAULT 0.00,
            is_recurring TINYINT(1) DEFAULT 1,
            effective_date DATE DEFAULT NULL,
            expiry_date DATE DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_employee (employee_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        // 3. Payroll Records (Generated Monthly Payslips)
        $mysqli->query("CREATE TABLE IF NOT EXISTS payroll_records (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_id VARCHAR(50) NOT NULL,
            payroll_month INT NOT NULL,
            payroll_year INT NOT NULL,
            base_salary DECIMAL(15, 2) NOT NULL,
            total_allowances DECIMAL(15, 2) DEFAULT 0.00,
            total_deductions DECIMAL(15, 2) DEFAULT 0.00,
            tax_amount DECIMAL(15, 2) DEFAULT 0.00,
            net_salary DECIMAL(15, 2) NOT NULL,
            status ENUM('Pending', 'Approved', 'Paid', 'Cancelled') DEFAULT 'Pending',
            payment_date DATE DEFAULT NULL,
            payment_method VARCHAR(50) DEFAULT NULL,
            remarks TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_payroll_period (employee_id, payroll_month, payroll_year),
            INDEX idx_employee (employee_id),
            INDEX idx_period (payroll_year, payroll_month)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    }
}

/**
 * Ensure announcements (App Banners) table exists.
 */
if (!function_exists('ensure_announcements_table')) {
    function ensure_announcements_table($mysqli) {
        $mysqli->query("CREATE TABLE IF NOT EXISTS announcements (
            id INT AUTO_INCREMENT PRIMARY KEY,
            admin_id VARCHAR(64) NOT NULL,
            title VARCHAR(255) NOT NULL,
            `text` TEXT,
            image_url VARCHAR(255) DEFAULT NULL,
            external_link VARCHAR(255) DEFAULT NULL,
            order_index INT DEFAULT 0,
            is_active TINYINT(1) DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_admin (admin_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // Migration: ensure 'admin_id' exists
        $check = $mysqli->query("SHOW COLUMNS FROM announcements LIKE 'admin_id'");
        if ($check && $check->num_rows == 0) {
            $mysqli->query("ALTER TABLE announcements ADD COLUMN admin_id VARCHAR(64) NOT NULL AFTER id");
            $mysqli->query("CREATE INDEX idx_admin ON announcements(admin_id)");
        }

        // Migration: ensure 'text' column
        $check = $mysqli->query("SHOW COLUMNS FROM announcements LIKE 'text'");
        if ($check && $check->num_rows == 0) {
            $mysqli->query("ALTER TABLE announcements ADD COLUMN `text` TEXT AFTER title");
        }

        // Migration: ensure 'image_url' exists
        $check = $mysqli->query("SHOW COLUMNS FROM announcements LIKE 'image_url'");
        if ($check && $check->num_rows == 0) {
            $mysqli->query("ALTER TABLE announcements ADD COLUMN image_url VARCHAR(255) DEFAULT NULL AFTER `text` ");
        }

        // Migration: ensure 'external_link' exists
        $check = $mysqli->query("SHOW COLUMNS FROM announcements LIKE 'external_link'");
        if ($check && $check->num_rows == 0) {
            $mysqli->query("ALTER TABLE announcements ADD COLUMN external_link VARCHAR(255) DEFAULT NULL AFTER image_url");
        }

        // Migration: ensure 'order_index' exists
        $check = $mysqli->query("SHOW COLUMNS FROM announcements LIKE 'order_index'");
        if ($check && $check->num_rows == 0) {
            $mysqli->query("ALTER TABLE announcements ADD COLUMN order_index INT DEFAULT 0 AFTER external_link");
        }

        // Migration: ensure 'is_active' exists
        $check = $mysqli->query("SHOW COLUMNS FROM announcements LIKE 'is_active'");
        if ($check && $check->num_rows == 0) {
            $mysqli->query("ALTER TABLE announcements ADD COLUMN is_active TINYINT(1) DEFAULT 1 AFTER order_index");
        }
    }
}

/**
 * Ensure training quiz tables exist.
 */
if (!function_exists('ensure_quiz_tables')) {
    function ensure_quiz_tables($mysqli) {
        $mysqli->query("CREATE TABLE IF NOT EXISTS training_quiz_questions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            question TEXT NOT NULL,
            option_a VARCHAR(255) NOT NULL,
            option_b VARCHAR(255) NOT NULL,
            option_c VARCHAR(255) NOT NULL,
            option_d VARCHAR(255) NOT NULL,
            correct_option ENUM('A', 'B', 'C', 'D') NOT NULL,
            explanation TEXT,
            is_active TINYINT(1) DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;");
    }
}


/**
 * Ensure Outstanding Staff Poll tables exist.
 */
if (!function_exists('ensure_staff_poll_tables')) {
    function ensure_staff_poll_tables($mysqli) {
        error_log("DB_SETUP: ensure_staff_poll_tables started");
        // 1. Poll Events (e.g. Month/Year)
        $q1 = $mysqli->query("CREATE TABLE IF NOT EXISTS poll_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            quarter VARCHAR(20) DEFAULT NULL,
            location VARCHAR(255) DEFAULT NULL,
            target_group_id INT DEFAULT NULL,
            target_employee_ids TEXT DEFAULT NULL,
            allow_multiple_votes TINYINT(1) DEFAULT 0,
            is_active TINYINT(1) DEFAULT 1,
            start_date DATE,
            end_date DATE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
        if (!$q1) {
            error_log("DB_SETUP: poll_events creation failed: " . $mysqli->error);
        }

        // Migration logic for existing tables - Check each column individually
        $cols = [
            'quarter' => "ALTER TABLE poll_events ADD COLUMN quarter VARCHAR(20) DEFAULT NULL AFTER description",
            'location' => "ALTER TABLE poll_events ADD COLUMN location VARCHAR(255) DEFAULT NULL AFTER quarter",
            'target_group_id' => "ALTER TABLE poll_events ADD COLUMN target_group_id INT DEFAULT NULL AFTER location",
            'target_employee_ids' => "ALTER TABLE poll_events ADD COLUMN target_employee_ids TEXT DEFAULT NULL AFTER target_group_id",
            'allow_multiple_votes' => "ALTER TABLE poll_events ADD COLUMN allow_multiple_votes TINYINT(1) DEFAULT 0 AFTER target_employee_ids",
            'is_active' => "ALTER TABLE poll_events ADD COLUMN is_active TINYINT(1) DEFAULT 1 AFTER allow_multiple_votes"
        ];
        foreach ($cols as $col => $sql) {
            $check = $mysqli->query("SHOW COLUMNS FROM poll_events LIKE '$col'");
            if ($check && $check->num_rows == 0) {
                $mysqli->query($sql);
            }
        }

        // 2. Candidates
        $q2 = $mysqli->query("CREATE TABLE IF NOT EXISTS poll_candidates (
            id INT AUTO_INCREMENT PRIMARY KEY,
            poll_id INT NOT NULL,
            employee_id VARCHAR(50) NOT NULL,
            category VARCHAR(100), -- 'Worker', 'Office', 'Warehouse'
            nomination_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (poll_id) REFERENCES poll_events(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
        if (!$q2) {
            error_log("DB_SETUP: poll_candidates creation failed: " . $mysqli->error);
        } else {
            error_log("DB_SETUP: poll_candidates creation checked/ok");
        }

        // 3. Votes
        $q3 = $mysqli->query("CREATE TABLE IF NOT EXISTS poll_votes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            poll_id INT NOT NULL,
            voter_employee_id VARCHAR(50) NOT NULL,
            candidate_id INT NOT NULL,
            voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY (poll_id, voter_employee_id), -- One person, one vote per event
            FOREIGN KEY (poll_id) REFERENCES poll_events(id) ON DELETE CASCADE,
            FOREIGN KEY (candidate_id) REFERENCES poll_candidates(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
        if (!$q3) {
            error_log("DB_SETUP: poll_votes creation failed: " . $mysqli->error);
        } else {
            error_log("DB_SETUP: poll_votes creation checked/ok");
        }
        error_log("DB_SETUP: ensure_staff_poll_tables finished");
    }
}

// Global execution for current $mysqli context if available
$mysqli_conn = $mysqli ?? ($GLOBALS['mysqli'] ?? null);
error_log("DB_SETUP: Checking mysqli. isset: " . (isset($mysqli_conn) ? 'YES' : 'NO'));
if ($mysqli_conn && $mysqli_conn instanceof mysqli) {
    $mysqli = $mysqli_conn;
    error_log("DB_SETUP: Global execution started");
    ensure_core_tables($mysqli);
    ensure_employment_columns_and_logs($mysqli);
    ensure_noted_column($mysqli);
    ensure_user_groups_table($mysqli);
    ensure_user_subaccounts_table($mysqli);
    ensure_column_visibility_table($mysqli);
    ensure_push_subscriptions_table($mysqli);
    ensure_meeting_tables($mysqli);
    ensure_notification_tables($mysqli);
    ensure_fcm_tokens_table($mysqli);
    ensure_payroll_tables($mysqli);
    ensure_announcements_table($mysqli);
    ensure_quiz_tables($mysqli);
    try {
        ensure_staff_poll_tables($mysqli);
    } catch (Throwable $e) {
        error_log("DB_SETUP: ensure_staff_poll_tables fatal error: " . $e->getMessage());
    }
    auto_resign_due_users($mysqli);
}
