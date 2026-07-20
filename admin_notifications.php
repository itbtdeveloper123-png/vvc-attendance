<?php
/**
 * admin_notifications.php
 */

$check_col = $mysqli->query("SHOW COLUMNS FROM notifications LIKE 'image_url'");
if ($check_col && $check_col->num_rows == 0) {
    $mysqli->query("ALTER TABLE notifications ADD COLUMN image_url VARCHAR(255) DEFAULT NULL AFTER expiry_date");
}

$history = [];
if ($h_res = $mysqli->query("SELECT * FROM notifications ORDER BY sent_at DESC LIMIT 120")) {
    while ($row = $h_res->fetch_assoc()) {
        $history[] = $row;
    }
}

$roles = [];
if ($r_res = $mysqli->query("SELECT DISTINCT system_role FROM users WHERE system_role IS NOT NULL AND system_role != '' ORDER BY system_role ASC")) {
    while ($row = $r_res->fetch_assoc()) {
        $roles[] = $row['system_role'];
    }
}
if (empty($roles)) {
    $roles = ['Admin', 'User'];
}

$users = [];
if ($u_res = $mysqli->query("SELECT employee_id, name FROM users WHERE employment_status = 'Active' ORDER BY name ASC")) {
    while ($row = $u_res->fetch_assoc()) {
        $users[] = $row;
    }
}

$templates = [];
if ($stmt = $mysqli->prepare("SELECT * FROM notification_templates WHERE admin_id = ? ORDER BY updated_at DESC, id DESC")) {
    $stmt->bind_param("s", $current_admin_id);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($res && $row = $res->fetch_assoc()) {
        $templates[] = $row;
    }
    $stmt->close();
}

$schedules = [];
if ($stmt = $mysqli->prepare("SELECT ns.*, nt.template_name FROM notification_schedules ns LEFT JOIN notification_templates nt ON ns.template_id = nt.id WHERE ns.admin_id = ? ORDER BY ns.updated_at DESC, ns.id DESC")) {
    $stmt->bind_param("s", $current_admin_id);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($res && $row = $res->fetch_assoc()) {
        $schedules[] = $row;
    }
    $stmt->close();
}
?>

<style>
    .notif-shell {
        display: flex;
        flex-direction: column;
        gap: 22px;
    }

    .notif-card {
        background: #fff;
        border: 1px solid #e2e8f0;
        border-radius: 18px;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.05);
        overflow: hidden;
    }

    .notif-card-header {
        padding: 20px 24px;
        border-bottom: 1px solid #e2e8f0;
        background: linear-gradient(135deg, rgba(99, 102, 241, 0.08), rgba(79, 70, 229, 0.03));
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
    }

    .notif-card-title {
        margin: 0;
        font-size: 1.15rem;
        font-weight: 800;
        color: #1e293b;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .notif-card-body {
        padding: 24px;
    }

    .notif-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 16px;
    }

    .notif-field {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-bottom: 16px;
    }

    .notif-field label {
        font-weight: 700;
        color: #334155;
        font-size: 0.9rem;
    }

    .notif-input,
    .notif-textarea,
    .notif-select {
        width: 100%;
        border: 1px solid #cbd5e1;
        border-radius: 12px;
        padding: 12px 14px;
        font: inherit;
        background: #f8fafc;
        color: #1e293b;
    }

    .notif-textarea {
        min-height: 110px;
        resize: vertical;
    }

    .notif-input:focus,
    .notif-textarea:focus,
    .notif-select:focus {
        outline: none;
        border-color: #6366f1;
        box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.12);
        background: #fff;
    }

    .notif-inline {
        display: flex;
        gap: 12px;
        align-items: center;
        flex-wrap: wrap;
    }

    .notif-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 7px 12px;
        border-radius: 999px;
        background: #eef2ff;
        color: #4338ca;
        font-size: 0.78rem;
        font-weight: 700;
    }

    .notif-actions {
        display: flex;
        gap: 10px;
        justify-content: flex-end;
        flex-wrap: wrap;
        margin-top: 8px;
    }

    .notif-btn {
        border: none;
        border-radius: 12px;
        padding: 11px 16px;
        font: inherit;
        font-weight: 700;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
    }

    .notif-btn:hover {
        transform: translateY(-1px);
    }

    .notif-btn-primary {
        background: linear-gradient(135deg, #6366f1, #4f46e5);
        color: #fff;
        box-shadow: 0 10px 18px rgba(99, 102, 241, 0.22);
    }

    .notif-btn-secondary {
        background: #e2e8f0;
        color: #334155;
    }

    .notif-btn-danger {
        background: #fee2e2;
        color: #b91c1c;
    }

    .notif-table-wrap {
        overflow-x: auto;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
    }

    .notif-table {
        width: 100%;
        border-collapse: collapse;
    }

    .notif-table th,
    .notif-table td {
        padding: 14px 16px;
        border-bottom: 1px solid #e2e8f0;
        text-align: left;
        vertical-align: top;
    }

    .notif-table th {
        background: #f8fafc;
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: #64748b;
    }

    .notif-table tr:last-child td {
        border-bottom: none;
    }

    .notif-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        border-radius: 999px;
        padding: 5px 10px;
        font-size: 0.76rem;
        font-weight: 800;
    }

    .notif-badge-success {
        background: #dcfce7;
        color: #166534;
    }

    .notif-badge-muted {
        background: #e2e8f0;
        color: #475569;
    }

    .notif-badge-warn {
        background: #fef3c7;
        color: #92400e;
    }

    .notif-helper {
        font-size: 0.8rem;
        color: #64748b;
    }

    .notif-image-preview {
        display: none;
        margin-top: 12px;
        max-width: 220px;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
    }

    @media (max-width: 768px) {
        .notif-card-body {
            padding: 18px;
        }
    }
</style>

<div id="notifications-module" class="action-section">
    <div class="section-container notif-shell">
        <div class="notif-card">
            <div class="notif-card-header">
                <h2 class="notif-card-title"><i class="fa-solid fa-paper-plane"></i> ផ្ញើ Notification ភ្លាមៗ</h2>
                <span class="notif-pill"><i class="fa-solid fa-bolt"></i> Instant Broadcast</span>
            </div>
            <div class="notif-card-body">
                <form id="send-notification-form" class="ajax-form" method="POST" action="admin_attendance.php" enctype="multipart/form-data">
                    <input type="hidden" name="ajax_action" value="save_notification">

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Apply Template</label>
                            <select id="send_template_picker" class="notif-select" onchange="applyTemplateToSendForm(this.value)">
                                <option value="">Custom Message</option>
                                <?php foreach ($templates as $template): ?>
                                    <option value="<?php echo (int) $template['id']; ?>"><?php echo htmlspecialchars($template['template_name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="notif-field">
                            <label>Expiry Date</label>
                            <input type="date" name="expiry_date" class="notif-input">
                        </div>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Title</label>
                            <input type="text" name="title" id="send_title" class="notif-input" required>
                        </div>
                        <div class="notif-field">
                            <label>Recipient Type</label>
                            <select name="target_type" id="nt-target-type" class="notif-select" onchange="toggleNotificationTargets()">
                                <option value="all">All Users</option>
                                <option value="role">By Role</option>
                                <option value="user">Specific Users</option>
                            </select>
                        </div>
                    </div>

                    <div class="notif-field">
                        <label>Message</label>
                        <textarea name="message" id="send_message" class="notif-textarea" required></textarea>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field" id="target-role-container" style="display:none;">
                            <label>Target Roles</label>
                            <div class="notif-inline">
                                <?php foreach ($roles as $role): ?>
                                    <label class="notif-pill" style="cursor:pointer;">
                                        <input type="checkbox" name="target_roles[]" value="<?php echo htmlspecialchars($role); ?>" style="accent-color:#6366f1;">
                                        <?php echo htmlspecialchars($role); ?>
                                    </label>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        <div class="notif-field" id="target-user-container" style="display:none;">
                            <label>Target Users</label>
                            <select name="target_users[]" id="send_target_users" class="notif-select" multiple size="7">
                                <?php foreach ($users as $user_row): ?>
                                    <option value="<?php echo htmlspecialchars($user_row['employee_id']); ?>">
                                        <?php echo htmlspecialchars($user_row['name'] . ' (' . $user_row['employee_id'] . ')'); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Image Upload</label>
                            <input type="file" name="notification_image" class="notif-input" accept="image/*" onchange="previewNotificationImage(this)">
                            <img id="notif-image-preview" class="notif-image-preview" alt="Preview">
                        </div>
                        <div class="notif-field">
                            <label>Template Placeholders</label>
                            <div class="notif-helper">
                                អ្នកអាចប្រើ `{{today}}`, `{{date}}`, `{{time}}`, `{{schedule_name}}`
                                នៅក្នុង Templates និង Schedules បាន។
                            </div>
                        </div>
                    </div>

                    <div class="notif-actions">
                        <button type="submit" class="notif-btn notif-btn-primary">
                            <i class="fa-solid fa-paper-plane"></i> Send Notification
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <div class="notif-card">
            <div class="notif-card-header">
                <h2 class="notif-card-title"><i class="fa-solid fa-layer-group"></i> Notification Templates</h2>
                <button type="button" class="notif-btn notif-btn-secondary" onclick="clearTemplateForm()">
                    <i class="fa-solid fa-rotate-left"></i> Clear
                </button>
            </div>
            <div class="notif-card-body">
                <form id="template-form" class="ajax-form" method="POST" action="admin_attendance.php">
                    <input type="hidden" name="ajax_action" value="save_notification_template">
                    <input type="hidden" name="template_id" id="template_id">

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Template Name</label>
                            <input type="text" name="template_name" id="template_name" class="notif-input" required>
                        </div>
                        <div class="notif-field">
                            <label>Template Key</label>
                            <input type="text" name="template_key" id="template_key" class="notif-input" placeholder="daily_reminder">
                        </div>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Title Template</label>
                            <input type="text" name="title_template" id="template_title" class="notif-input" required>
                        </div>
                        <div class="notif-field">
                            <label>Image URL</label>
                            <input type="text" name="image_url" id="template_image_url" class="notif-input" placeholder="https://...">
                        </div>
                    </div>

                    <div class="notif-field">
                        <label>Message Template</label>
                        <textarea name="message_template" id="template_message" class="notif-textarea" required></textarea>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Default Target Type</label>
                            <select name="target_type" id="template_target_type" class="notif-select">
                                <option value="all">All Users</option>
                                <option value="role">By Role</option>
                                <option value="user">Specific Users</option>
                            </select>
                        </div>
                        <div class="notif-field">
                            <label>Status</label>
                            <label class="notif-inline">
                                <input type="checkbox" name="is_active" id="template_is_active" checked>
                                <span class="notif-helper">Active</span>
                            </label>
                        </div>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Target Roles (comma or line separated)</label>
                            <textarea name="target_roles_text" id="template_roles_text" class="notif-textarea" style="min-height:90px;"></textarea>
                        </div>
                        <div class="notif-field">
                            <label>Target Users (employee IDs)</label>
                            <textarea name="target_users_text" id="template_users_text" class="notif-textarea" style="min-height:90px;"></textarea>
                        </div>
                    </div>

                    <div class="notif-actions">
                        <button type="submit" class="notif-btn notif-btn-primary">
                            <i class="fa-solid fa-floppy-disk"></i> Save Template
                        </button>
                    </div>
                </form>

                <div class="notif-table-wrap" style="margin-top:24px;">
                    <table class="notif-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Target</th>
                                <th>Preview</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($templates)): ?>
                                <tr><td colspan="5" style="text-align:center; color:#64748b;">មិនទាន់មាន Template នៅឡើយទេ។</td></tr>
                            <?php endif; ?>
                            <?php foreach ($templates as $template): ?>
                                <?php
                                $template_payload = htmlspecialchars(enterprise_json_encode($template), ENT_QUOTES, 'UTF-8');
                                $target_label = $template['target_type'] === 'role' ? 'Roles' : ($template['target_type'] === 'user' ? 'Users' : 'All');
                                ?>
                                <tr>
                                    <td>
                                        <div style="font-weight:800;"><?php echo htmlspecialchars($template['template_name']); ?></div>
                                        <div class="notif-helper"><?php echo htmlspecialchars($template['template_key'] ?? ''); ?></div>
                                    </td>
                                    <td><?php echo htmlspecialchars($target_label); ?></td>
                                    <td>
                                        <div style="font-weight:700;"><?php echo htmlspecialchars($template['title_template']); ?></div>
                                        <div class="notif-helper"><?php echo htmlspecialchars(mb_strimwidth((string) $template['message_template'], 0, 80, '...')); ?></div>
                                    </td>
                                    <td>
                                        <span class="notif-badge <?php echo !empty($template['is_active']) ? 'notif-badge-success' : 'notif-badge-muted'; ?>">
                                            <?php echo !empty($template['is_active']) ? 'Active' : 'Inactive'; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <div class="notif-inline">
                                            <button type="button" class="notif-btn notif-btn-secondary" onclick='editNotificationTemplate(<?php echo $template_payload; ?>)'>
                                                <i class="fa-solid fa-pen-to-square"></i> Edit
                                            </button>
                                            <button type="button" class="notif-btn notif-btn-danger" onclick="deleteNotificationTemplate(<?php echo (int) $template['id']; ?>)">
                                                <i class="fa-solid fa-trash"></i> Delete
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="notif-card">
            <div class="notif-card-header">
                <h2 class="notif-card-title"><i class="fa-solid fa-calendar-days"></i> Notification Schedules</h2>
                <button type="button" class="notif-btn notif-btn-secondary" onclick="clearScheduleForm()">
                    <i class="fa-solid fa-rotate-left"></i> Clear
                </button>
            </div>
            <div class="notif-card-body">
                <form id="schedule-form" class="ajax-form" method="POST" action="admin_attendance.php">
                    <input type="hidden" name="ajax_action" value="save_notification_schedule">
                    <input type="hidden" name="schedule_id" id="schedule_id">

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Schedule Name</label>
                            <input type="text" name="schedule_name" id="schedule_name" class="notif-input" required>
                        </div>
                        <div class="notif-field">
                            <label>Template</label>
                            <select name="template_id" id="schedule_template_id" class="notif-select">
                                <option value="0">No Template</option>
                                <?php foreach ($templates as $template): ?>
                                    <option value="<?php echo (int) $template['id']; ?>"><?php echo htmlspecialchars($template['template_name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Frequency</label>
                            <select name="frequency" id="schedule_frequency" class="notif-select" onchange="toggleScheduleFields()">
                                <option value="once">Once</option>
                                <option value="daily">Daily</option>
                                <option value="weekly">Weekly</option>
                                <option value="monthly">Monthly</option>
                            </select>
                        </div>
                        <div class="notif-field">
                            <label>Status</label>
                            <label class="notif-inline">
                                <input type="checkbox" name="is_active" id="schedule_is_active" checked>
                                <span class="notif-helper">Active</span>
                            </label>
                        </div>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field" id="schedule_once_wrap">
                            <label>Scheduled At</label>
                            <input type="datetime-local" name="scheduled_at" id="schedule_scheduled_at" class="notif-input">
                        </div>
                        <div class="notif-field" id="schedule_time_wrap" style="display:none;">
                            <label>Time of Day</label>
                            <input type="time" name="time_of_day" id="schedule_time_of_day" class="notif-input" value="09:00">
                        </div>
                        <div class="notif-field" id="schedule_week_wrap" style="display:none;">
                            <label>Day of Week</label>
                            <select name="day_of_week" id="schedule_day_of_week" class="notif-select">
                                <option value="0">Sunday</option>
                                <option value="1">Monday</option>
                                <option value="2">Tuesday</option>
                                <option value="3">Wednesday</option>
                                <option value="4">Thursday</option>
                                <option value="5">Friday</option>
                                <option value="6">Saturday</option>
                            </select>
                        </div>
                        <div class="notif-field" id="schedule_month_wrap" style="display:none;">
                            <label>Day of Month</label>
                            <input type="number" name="day_of_month" id="schedule_day_of_month" class="notif-input" min="1" max="31" value="1">
                        </div>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Title Override</label>
                            <input type="text" name="title_override" id="schedule_title_override" class="notif-input">
                        </div>
                        <div class="notif-field">
                            <label>Image URL</label>
                            <input type="text" name="image_url" id="schedule_image_url" class="notif-input" placeholder="https://...">
                        </div>
                    </div>

                    <div class="notif-field">
                        <label>Message Override</label>
                        <textarea name="message_override" id="schedule_message_override" class="notif-textarea"></textarea>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Target Type Override</label>
                            <select name="target_type" id="schedule_target_type" class="notif-select">
                                <option value="">Use Template / Default</option>
                                <option value="all">All Users</option>
                                <option value="role">By Role</option>
                                <option value="user">Specific Users</option>
                            </select>
                        </div>
                    </div>

                    <div class="notif-grid">
                        <div class="notif-field">
                            <label>Target Roles Override</label>
                            <textarea name="target_roles_text" id="schedule_roles_text" class="notif-textarea" style="min-height:90px;"></textarea>
                        </div>
                        <div class="notif-field">
                            <label>Target Users Override</label>
                            <textarea name="target_users_text" id="schedule_users_text" class="notif-textarea" style="min-height:90px;"></textarea>
                        </div>
                    </div>

                    <div class="notif-actions">
                        <button type="submit" class="notif-btn notif-btn-primary">
                            <i class="fa-solid fa-floppy-disk"></i> Save Schedule
                        </button>
                    </div>
                </form>

                <div class="notif-table-wrap" style="margin-top:24px;">
                    <table class="notif-table">
                        <thead>
                            <tr>
                                <th>Schedule</th>
                                <th>Frequency</th>
                                <th>Next Run</th>
                                <th>Last Result</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($schedules)): ?>
                                <tr><td colspan="5" style="text-align:center; color:#64748b;">មិនទាន់មាន Schedule នៅឡើយទេ។</td></tr>
                            <?php endif; ?>
                            <?php foreach ($schedules as $schedule): ?>
                                <?php $schedule_payload = htmlspecialchars(enterprise_json_encode($schedule), ENT_QUOTES, 'UTF-8'); ?>
                                <tr>
                                    <td>
                                        <div style="font-weight:800;"><?php echo htmlspecialchars($schedule['schedule_name']); ?></div>
                                        <div class="notif-helper"><?php echo htmlspecialchars($schedule['template_name'] ?? 'Custom schedule'); ?></div>
                                    </td>
                                    <td><?php echo htmlspecialchars(ucfirst((string) $schedule['frequency'])); ?></td>
                                    <td>
                                        <div><?php echo htmlspecialchars($schedule['next_run_at'] ?? '—'); ?></div>
                                        <div class="notif-helper"><?php echo !empty($schedule['is_active']) ? 'Active' : 'Paused'; ?></div>
                                    </td>
                                    <td>
                                        <span class="notif-badge <?php echo ($schedule['last_result'] ?? '') === 'success' ? 'notif-badge-success' : (($schedule['last_result'] ?? '') === 'error' ? 'notif-badge-warn' : 'notif-badge-muted'); ?>">
                                            <?php echo htmlspecialchars($schedule['last_result'] ?: 'waiting'); ?>
                                        </span>
                                        <div class="notif-helper"><?php echo htmlspecialchars($schedule['last_message'] ?? ''); ?></div>
                                    </td>
                                    <td>
                                        <div class="notif-inline">
                                            <button type="button" class="notif-btn notif-btn-secondary" onclick='editNotificationSchedule(<?php echo $schedule_payload; ?>)'>
                                                <i class="fa-solid fa-pen-to-square"></i> Edit
                                            </button>
                                            <button type="button" class="notif-btn notif-btn-secondary" onclick="toggleNotificationSchedule(<?php echo (int) $schedule['id']; ?>)">
                                                <i class="fa-solid <?php echo !empty($schedule['is_active']) ? 'fa-pause' : 'fa-play'; ?>"></i>
                                                <?php echo !empty($schedule['is_active']) ? 'Pause' : 'Resume'; ?>
                                            </button>
                                            <button type="button" class="notif-btn notif-btn-danger" onclick="deleteNotificationSchedule(<?php echo (int) $schedule['id']; ?>)">
                                                <i class="fa-solid fa-trash"></i> Delete
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="notif-card">
            <div class="notif-card-header">
                <h2 class="notif-card-title"><i class="fa-solid fa-clock-rotate-left"></i> Notification History</h2>
                <button type="button" class="notif-btn notif-btn-danger" onclick="bulkDeleteNotifications()">
                    <i class="fa-solid fa-trash-can"></i> Delete Selected
                </button>
            </div>
            <div class="notif-card-body">
                <div class="notif-table-wrap">
                    <table class="notif-table">
                        <thead>
                            <tr>
                                <th style="width:40px; text-align:center;">
                                    <input type="checkbox" id="check-all-notifications" onclick="toggleAllNotifications(this)">
                                </th>
                                <th>ID</th>
                                <th>Title / Message</th>
                                <th>Recipient</th>
                                <th>Sent At</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($history)): ?>
                                <tr><td colspan="6" style="text-align:center; color:#64748b;">មិនទាន់មានប្រវត្តិផ្ញើ Notification នៅឡើយទេ។</td></tr>
                            <?php endif; ?>
                            <?php foreach ($history as $row): ?>
                                <tr id="notif-row-<?php echo (int) $row['id']; ?>">
                                    <td style="text-align:center;">
                                        <input type="checkbox" class="notif-checkbox" value="<?php echo (int) $row['id']; ?>">
                                    </td>
                                    <td>#<?php echo (int) $row['id']; ?></td>
                                    <td>
                                        <div style="font-weight:800;"><?php echo htmlspecialchars($row['title']); ?></div>
                                        <div class="notif-helper"><?php echo htmlspecialchars(mb_strimwidth((string) $row['message'], 0, 100, '...')); ?></div>
                                    </td>
                                    <td><?php echo htmlspecialchars($row['recipient_type'] ?? 'all'); ?></td>
                                    <td><?php echo !empty($row['sent_at']) ? date('d/m/Y H:i', strtotime($row['sent_at'])) : '—'; ?></td>
                                    <td>
                                        <button type="button" class="notif-btn notif-btn-danger" onclick="deleteNotification(<?php echo (int) $row['id']; ?>)">
                                            <i class="fa-solid fa-trash"></i> Delete
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    const notificationTemplates = <?php echo enterprise_json_encode($templates); ?>;

    function previewNotificationImage(input) {
        const preview = document.getElementById('notif-image-preview');
        if (!preview) return;
        if (input.files && input.files[0]) {
            const reader = new FileReader();
            reader.onload = function (event) {
                preview.src = event.target.result;
                preview.style.display = 'block';
            };
            reader.readAsDataURL(input.files[0]);
        } else {
            preview.style.display = 'none';
            preview.removeAttribute('src');
        }
    }

    function toggleNotificationTargets() {
        const type = document.getElementById('nt-target-type')?.value || 'all';
        const roleWrap = document.getElementById('target-role-container');
        const userWrap = document.getElementById('target-user-container');
        if (roleWrap) roleWrap.style.display = type === 'role' ? 'block' : 'none';
        if (userWrap) userWrap.style.display = type === 'user' ? 'block' : 'none';
    }

    function toggleScheduleFields() {
        const freq = document.getElementById('schedule_frequency')?.value || 'once';
        const onceWrap = document.getElementById('schedule_once_wrap');
        const timeWrap = document.getElementById('schedule_time_wrap');
        const weekWrap = document.getElementById('schedule_week_wrap');
        const monthWrap = document.getElementById('schedule_month_wrap');
        if (onceWrap) onceWrap.style.display = freq === 'once' ? 'block' : 'none';
        if (timeWrap) timeWrap.style.display = freq === 'once' ? 'none' : 'block';
        if (weekWrap) weekWrap.style.display = freq === 'weekly' ? 'block' : 'none';
        if (monthWrap) monthWrap.style.display = freq === 'monthly' ? 'block' : 'none';
    }

    function applyTemplateToSendForm(templateId) {
        const id = parseInt(templateId || '0', 10);
        const template = notificationTemplates.find(item => parseInt(item.id, 10) === id);
        if (!template) return;

        document.getElementById('send_title').value = template.title_template || '';
        document.getElementById('send_message').value = template.message_template || '';
        document.getElementById('nt-target-type').value = template.target_type || 'all';
        toggleNotificationTargets();

        document.querySelectorAll('input[name="target_roles[]"]').forEach(box => {
            box.checked = false;
        });
        try {
            const roles = JSON.parse(template.target_roles_json || '[]');
            document.querySelectorAll('input[name="target_roles[]"]').forEach(box => {
                if (roles.includes(box.value)) box.checked = true;
            });
        } catch (err) { }

        const userSelect = document.getElementById('send_target_users');
        if (userSelect) {
            Array.from(userSelect.options).forEach(option => option.selected = false);
            try {
                const users = JSON.parse(template.target_users_json || '[]');
                Array.from(userSelect.options).forEach(option => {
                    if (users.includes(option.value)) option.selected = true;
                });
            } catch (err) { }
        }
    }

    function clearTemplateForm() {
        const form = document.getElementById('template-form');
        if (!form) return;
        form.reset();
        document.getElementById('template_id').value = '';
        document.getElementById('template_is_active').checked = true;
    }

    function editNotificationTemplate(payload) {
        const template = (typeof payload === 'string') ? JSON.parse(payload) : payload;
        document.getElementById('template_id').value = template.id || '';
        document.getElementById('template_name').value = template.template_name || '';
        document.getElementById('template_key').value = template.template_key || '';
        document.getElementById('template_title').value = template.title_template || '';
        document.getElementById('template_message').value = template.message_template || '';
        document.getElementById('template_target_type').value = template.target_type || 'all';
        document.getElementById('template_roles_text').value = parseJsonList(template.target_roles_json).join("\n");
        document.getElementById('template_users_text').value = parseJsonList(template.target_users_json).join("\n");
        document.getElementById('template_image_url').value = template.image_url || '';
        document.getElementById('template_is_active').checked = parseInt(template.is_active || '0', 10) === 1;
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function clearScheduleForm() {
        const form = document.getElementById('schedule-form');
        if (!form) return;
        form.reset();
        document.getElementById('schedule_id').value = '';
        document.getElementById('schedule_is_active').checked = true;
        document.getElementById('schedule_frequency').value = 'once';
        toggleScheduleFields();
    }

    function editNotificationSchedule(payload) {
        const schedule = (typeof payload === 'string') ? JSON.parse(payload) : payload;
        document.getElementById('schedule_id').value = schedule.id || '';
        document.getElementById('schedule_name').value = schedule.schedule_name || '';
        document.getElementById('schedule_template_id').value = schedule.template_id || '0';
        document.getElementById('schedule_frequency').value = schedule.frequency || 'once';
        document.getElementById('schedule_scheduled_at').value = toDatetimeLocal(schedule.scheduled_at || '');
        document.getElementById('schedule_time_of_day').value = schedule.time_of_day || '09:00';
        document.getElementById('schedule_day_of_week').value = schedule.day_of_week ?? '0';
        document.getElementById('schedule_day_of_month').value = schedule.day_of_month ?? '1';
        document.getElementById('schedule_title_override').value = schedule.title_override || '';
        document.getElementById('schedule_message_override').value = schedule.message_override || '';
        document.getElementById('schedule_target_type').value = schedule.target_type || '';
        document.getElementById('schedule_roles_text').value = parseJsonList(schedule.target_roles_json).join("\n");
        document.getElementById('schedule_users_text').value = parseJsonList(schedule.target_users_json).join("\n");
        document.getElementById('schedule_image_url').value = schedule.image_url || '';
        document.getElementById('schedule_is_active').checked = parseInt(schedule.is_active || '0', 10) === 1;
        toggleScheduleFields();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function parseJsonList(value) {
        if (!value) return [];
        if (Array.isArray(value)) return value.filter(Boolean);
        try {
            const parsed = JSON.parse(value);
            if (Array.isArray(parsed)) return parsed.filter(Boolean);
        } catch (err) { }
        return String(value).split(/[\r\n,]+/).map(item => item.trim()).filter(Boolean);
    }

    function toDatetimeLocal(value) {
        if (!value) return '';
        return String(value).replace(' ', 'T').slice(0, 16);
    }

    function postNotificationAction(formData) {
        return fetch('admin_attendance.php', { method: 'POST', body: formData }).then(res => res.json());
    }

    function deleteNotificationTemplate(id) {
        if (!confirm('តើអ្នកប្រាកដថាចង់លុប Template នេះទេ?')) return;
        const fd = new FormData();
        fd.append('ajax_action', 'delete_notification_template');
        fd.append('template_id', id);
        postNotificationAction(fd).then(json => {
            showAjaxMessage(json.status === 'success' ? 'success' : 'error', json.message || 'Done');
            if (json.status === 'success') setTimeout(() => location.reload(), 900);
        }).catch(err => showAjaxMessage('error', 'Network error: ' + err));
    }

    function toggleNotificationSchedule(id) {
        const fd = new FormData();
        fd.append('ajax_action', 'toggle_notification_schedule');
        fd.append('schedule_id', id);
        postNotificationAction(fd).then(json => {
            showAjaxMessage(json.status === 'success' ? 'success' : 'error', json.message || 'Done');
            if (json.status === 'success') setTimeout(() => location.reload(), 900);
        }).catch(err => showAjaxMessage('error', 'Network error: ' + err));
    }

    function deleteNotificationSchedule(id) {
        if (!confirm('តើអ្នកប្រាកដថាចង់លុប Schedule នេះទេ?')) return;
        const fd = new FormData();
        fd.append('ajax_action', 'delete_notification_schedule');
        fd.append('schedule_id', id);
        postNotificationAction(fd).then(json => {
            showAjaxMessage(json.status === 'success' ? 'success' : 'error', json.message || 'Done');
            if (json.status === 'success') setTimeout(() => location.reload(), 900);
        }).catch(err => showAjaxMessage('error', 'Network error: ' + err));
    }

    function toggleAllNotifications(source) {
        document.querySelectorAll('.notif-checkbox').forEach(box => box.checked = source.checked);
    }

    function deleteNotification(id) {
        if (!confirm('តើអ្នកប្រាកដថាចង់លុប Notification នេះទេ?')) return;
        const fd = new FormData();
        fd.append('ajax_action', 'delete_notifications');
        fd.append('ids[]', id);
        postNotificationAction(fd).then(json => {
            if (json.status === 'success') {
                document.getElementById('notif-row-' + id)?.remove();
            }
            showAjaxMessage(json.status === 'success' ? 'success' : 'error', json.message || 'Done');
        }).catch(err => showAjaxMessage('error', 'Network error: ' + err));
    }

    function bulkDeleteNotifications() {
        const ids = Array.from(document.querySelectorAll('.notif-checkbox:checked')).map(box => box.value);
        if (ids.length === 0) {
            showAjaxMessage('warning', 'សូមជ្រើសរើស Notification យ៉ាងហោចណាស់មួយ។');
            return;
        }
        if (!confirm('តើអ្នកប្រាកដថាចង់លុប Notification ចំនួន ' + ids.length + ' មែនទេ?')) return;
        const fd = new FormData();
        fd.append('ajax_action', 'delete_notifications');
        ids.forEach(id => fd.append('ids[]', id));
        postNotificationAction(fd).then(json => {
            showAjaxMessage(json.status === 'success' ? 'success' : 'error', json.message || 'Done');
            if (json.status === 'success') {
                ids.forEach(id => document.getElementById('notif-row-' + id)?.remove());
                document.getElementById('check-all-notifications').checked = false;
            }
        }).catch(err => showAjaxMessage('error', 'Network error: ' + err));
    }

    document.addEventListener('DOMContentLoaded', function () {
        toggleNotificationTargets();
        toggleScheduleFields();
    });
</script>
