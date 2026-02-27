<?php
// បង្ហាញ Error ទាំងអស់សម្រាប់ Debugging (បិទ comment ពេលដាក់ឲ្យដំណើរការจริง)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

//======================================================================
// ១. ការកំណត់ (CONFIGURATION)
//======================================================================
define('BOT_TOKEN', '7680086124:AAHrvdz-mOx3pO1Ijqvh7BHTeGh2JB5JuwQ'); // <<<--- សូមដាក់ BOT TOKEN របស់អ្នក
define('API_URL', 'https://api.telegram.org/bot' . BOT_TOKEN . '/');
define('DATA_FILE', __DIR__ . '/data.json');
define('ERROR_LOG_FILE', __DIR__ . '/bot_errors.log');
define('UPDATE_LOG_FILE', __DIR__ . '/updates.log'); // <<<--- បន្ថែម​បន្ទាត់​នេះ
define('USD_TO_KHR_RATE', 4100); // <<<--- កំណត់អត្រាប្តូរប្រាក់នៅទីនេះ 1 USD = 4100 KHR
date_default_timezone_set('Asia/Phnom_Penh');

//======================================================================
// ២. មុខងារសម្រាប់ទំនាក់ទំនងជាមួយ TELEGRAM API (HELPER FUNCTIONS)
//======================================================================
function logError($message) {
    $timestamp = date("Y-m-d H:i:s");
    file_put_contents(ERROR_LOG_FILE, "[$timestamp] $message\n", FILE_APPEND);
}

set_error_handler(function($severity, $message, $file, $line) {
    logError("PHP Error: [$severity] $message in $file on line $line");
});

function apiRequest($method, $data) {
    $options = ['http' => ['header'  => "Content-type: application/json\r\n", 'method'  => 'POST', 'content' => json_encode($data), 'ignore_errors' => true]];
    $context  = stream_context_create($options);
    $result = @file_get_contents(API_URL . $method, false, $context);
    if ($result === FALSE) { logError("API Request Failed: Unable to connect to Telegram API or invalid response."); return null; }
    return $result;
}

function sendMessage($chat_id, $text, $parse_mode = 'HTML', $reply_markup = null) {
    $data = ['chat_id' => $chat_id, 'text' => $text, 'parse_mode' => $parse_mode];
    if ($reply_markup) { $data['reply_markup'] = $reply_markup; }
    apiRequest('sendMessage', $data);
}

function answerCallbackQuery($callback_query_id, $text = '', $show_alert = false) {
    apiRequest('answerCallbackQuery', ['callback_query_id' => $callback_query_id, 'text' => $text, 'show_alert' => $show_alert]);
}

function editMessageText($chat_id, $message_id, $text, $parse_mode = 'HTML', $keyboard = null) {
    $data = ['chat_id' => $chat_id, 'message_id' => $message_id, 'text' => $text, 'parse_mode' => $parse_mode];
    if ($keyboard) { $data['reply_markup'] = $keyboard; }
    apiRequest('editMessageText', $data);
}

//======================================================================
// ៣. មុខងារគ្រប់គ្រងទិន្នន័យ (DATA FUNCTIONS)
//======================================================================
function readData() {
    if (!file_exists(DATA_FILE) || filesize(DATA_FILE) === 0) { return []; }
    $fp = fopen(DATA_FILE, 'r');
    if (!$fp) { logError("Failed to open data file for reading: " . DATA_FILE); return []; }
    flock($fp, LOCK_SH);
    $json_data = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    $data = json_decode($json_data, true);
    return is_array($data) ? $data : [];
}

function writeData($data) {
    $fp = fopen(DATA_FILE, 'w');
    if (!$fp) { logError("Failed to open data file for writing: " . DATA_FILE); return false; }
    flock($fp, LOCK_EX);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    flock($fp, LOCK_UN);
    fclose($fp);
    return true;
}

//======================================================================
// ៤. មុខងារបង្កើតប្រតិទិន (CALENDAR GENERATOR)
//======================================================================
function generateCalendar($year, $month) {
    $firstDayOfMonth = mktime(0, 0, 0, $month, 1, $year);
    $monthNameKh = [1 => 'មករា', 'កុម្ភៈ', 'មីនា', 'មេសា', 'ឧសភា', 'មិថុនា', 'កក្កដា', 'សីហា', 'កញ្ញា', 'តុលា', 'វិច្ឆិកា', 'ធ្នូ'];
    $currentMonthName = $monthNameKh[(int)date('m', $firstDayOfMonth)];
    $keyboard = [];
    $prevMonthDate = date('Y-m', strtotime('-1 month', $firstDayOfMonth));
    $nextMonthDate = date('Y-m', strtotime('+1 month', $firstDayOfMonth));
    $keyboard[] = [['text' => '◀️', 'callback_data' => 'nav_' . $prevMonthDate], ['text' => "🗓️ $currentMonthName $year", 'callback_data' => 'ignore_month_label'], ['text' => '▶️', 'callback_data' => 'nav_' . $nextMonthDate]];
    $daysOfWeek = ['អាទិត្យ', 'ចន្ទ', 'អង្គារ', 'ពុធ', 'ព្រហស្បតិ៍', 'សុក្រ', 'សៅរ៍'];
    $dayLabels = [];
    foreach ($daysOfWeek as $day) { $dayLabels[] = ['text' => mb_substr($day, 0, 2, 'UTF-8'), 'callback_data' => 'ignore_day_label']; }
    $keyboard[] = $dayLabels;
    $daysInMonth = date('t', $firstDayOfMonth);
    $startDayOfWeek = date('w', $firstDayOfMonth);
    $currentDay = 1;
    $row = [];
    for ($i = 0; $i < $startDayOfWeek; $i++) { $row[] = ['text' => ' ', 'callback_data' => 'ignore_empty']; }
    while ($currentDay <= $daysInMonth) {
        if (count($row) == 7) { $keyboard[] = $row; $row = []; }
        $date = sprintf('%04d-%02d-%02d', $year, $month, $currentDay);
        $row[] = ['text' => (string)$currentDay, 'callback_data' => 'select_date_' . $date];
        $currentDay++;
    }
    if (!empty($row)) {
        while (count($row) < 7) { $row[] = ['text' => ' ', 'callback_data' => 'ignore_empty']; }
        $keyboard[] = $row;
    }
    $keyboard[] = [['text' => '↩️ ត្រឡប់ទៅម៉ឺនុយរបាយការណ៍', 'callback_data' => 'back_to_report_menu']];
    return ['inline_keyboard' => $keyboard];
}

//======================================================================
// ៥. ផ្នែកដំណើរការหลัก (MAIN LOGIC)
//======================================================================
$update_json = file_get_contents('php://input');
if (!$update_json) { exit(); }
$update = json_decode($update_json, true);

if (isset($update['message'])) {
    $message = $update['message'];
    $chat_id = $message['chat']['id'];
    $text = isset($message['text']) ? $message['text'] : (isset($message['caption']) ? $message['caption'] : '');


    if (strpos($text, '/start') === 0) {
        sendMessage($chat_id, "👋 <b>សូមស្វាគមន៍!</b>\n\n💰 រាល់តួលេខដែលអ្នកបញ្ចូលនឹងត្រូវបានចាត់ទុកជាប្រាក់ដុល្លារ (USD) ដោយស្វ័យប្រវត្តិ។\n\n<b><u>ឧទាហរណ៍</u>:</b>\n\$50 (ប្រភេទ ABA)\n50 USD (ប្រភេទ AC)\n\n<b><u>ពាក្យបញ្ជាចម្បង</u>:</b>\n/summary - របាយការណ៍សរុបរហ័ស\n/report - ជម្រើសរបាយការណ៍លម្អិត\n/clear - សម្អាតទិន្នន័យទាំងអស់");
    
    } elseif (strpos($text, '/summary') === 0) {
        $all_data = readData();
        $chat_data = isset($all_data[$chat_id]) && is_array($all_data[$chat_id]) ? $all_data[$chat_id] : [];
        
        $totals_usd = ['today' => 0, 'grand' => 0];
        $counts = ['today' => 0, 'grand' => 0];
        $totals_usd_shifts = ['morning' => 0, 'afternoon' => 0, 'night' => 0];
        $today_date = date('Y-m-d');
        
        foreach ($chat_data as $entry) {
            if (is_array($entry) && isset($entry['value'])) {
                $entry_date = null;
                $has_time_info = false;
                if (isset($entry['datetime'])) {
                    $entry_date = substr($entry['datetime'], 0, 10);
                    $has_time_info = true;
                } elseif (isset($entry['date'])) {
                    $entry_date = $entry['date'];
                } else { continue; }

                $value = (float) $entry['value'];
                $totals_usd['grand'] += $value;
                $counts['grand']++;

                if ($entry_date === $today_date) {
                    $totals_usd['today'] += $value;
                    $counts['today']++;
                    if ($has_time_info) {
                        $hour = (int)substr($entry['datetime'], 11, 2);
                        if ($hour >= 5 && $hour < 12) { $totals_usd_shifts['morning'] += $value; } 
                        elseif ($hour >= 12 && $hour < 21) { $totals_usd_shifts['afternoon'] += $value; } 
                        else { $totals_usd_shifts['night'] += $value; }
                    }
                }
            }
        }
        
        $response  = "📊 <b>សង្ខេបសរុបប្រចាំថ្ងៃ</b>\n";
        $response .= "━━━━━━━━━━━━━━━━\n\n";

        $response .= "🗓️ <b>ថ្ងៃនេះ</b>\n";
        $response .= "  \n • ប្រតិបត្តិការ៖ <b>{$counts['today']}</b> ដង\n";
        $response .= "   • 💵 USD: <b>" . number_format($totals_usd['today'], 2) . "</b>\n";
        $response .= "   • 💰 KHR: <b>" . number_format($totals_usd['today'] * USD_TO_KHR_RATE, 0) . " ៛</b>\n";

        $response .= "\n🕒 <b>តាមវេន</b>\n";
        $response .= " \n  🌅 ព្រឹក: <b>" . number_format($totals_usd_shifts['morning'], 2) . "</b> USD\n";
        $response .= " \n  🌇 ល្ងាច: <b>" . number_format($totals_usd_shifts['afternoon'], 2) . "</b> USD\n";
        $response .= " \n  🌃 យប់: <b>" . number_format($totals_usd_shifts['night'], 2) . "</b> USD\n";

        $response .= "\n📦 <b>សរុបរួម</b>\n";
        $response .= "  \n • ប្រតិបត្តិការ៖ <b>{$counts['grand']}</b> ដង\n";
        $response .= "   • 💵 USD: <b>" . number_format($totals_usd['grand'], 2) . "</b>\n";
        $response .= "   • 💰 KHR: <b>" . number_format($totals_usd['grand'] * USD_TO_KHR_RATE, 0) . " ៛</b>\n";

        $response .= "\n━━━━━━━━━━━━━━━━\n";
        $response .= "📌 <i>អត្រាប្តូរ:</i> 1 USD = " . number_format(USD_TO_KHR_RATE, 0) . "៛";
        sendMessage($chat_id, $response, 'HTML');

    } elseif (strpos($text, '/clear') === 0 || strpos($text, '/reset') === 0) {
        $all_data = readData();
        $all_data[$chat_id] = [];
        if (writeData($all_data)) { sendMessage($chat_id, "✅ ទិន្នន័យទាំងអស់ត្រូវបានសម្អាតរួចរាល់ហើយ។"); } 
        else { sendMessage($chat_id, "❌ មានបញ្ហាក្នុងការសម្អាតទិន្នន័យ។ សូមព្យាយាមម្តងទៀត។"); }
        
    } elseif (strpos($text, '/report') === 0) {
        $report_menu_keyboard = ['inline_keyboard' => [[['text' => '✅ ថ្ងៃនេះ (' . date('d M') . ')', 'callback_data' => 'select_date_today']], [['text' => '⏪ ម្សិលមិញ', 'callback_data' => 'select_date_yesterday']], [['text' => '📅 ជ្រើសរើសថ្ងៃខែឆ្នាំមើលរបាយការណ៍', 'callback_data' => 'show_calendar']]]];
        sendMessage($chat_id, "📋 សូមជ្រើសរើសរបាយការណ៍ដែលអ្នកចង់មើល៖", 'HTML', $report_menu_keyboard);
    
    } else {
        // --- [START OF MODIFIED BLOCK] ---
        // regex នេះ​អាច​ចាប់​បាន​ទាំង​ពីរ​ទម្រង់:
        // 1. $11.10 ... (ចាប់​យក 11.10 ចូល​ទៅ​ក្នុង $match[1])
        // 2. Received 6.00 USD ... (ចាប់​យក 6.00 ចូល​ទៅ​ក្នុង $match[2])
        preg_match_all('/\$(\d+(?:\.\d+)?)|Received\s+(\d+(?:\.\d+)?)\s+USD/i', $text, $matches, PREG_SET_ORDER);

        if (!empty($matches)) {
            $all_data = readData();
            $chat_data = isset($all_data[$chat_id]) && is_array($all_data[$chat_id]) ? $all_data[$chat_id] : [];

            foreach ($matches as $match) {
                $number = 0;
                $type = null;

                // ពិនិត្យ​មើល​ថា​តើ​វា​ត្រូវ​នឹង​ទម្រង់ទី១ ($xx.xx) ដែរ​ឬទេ
                if (isset($match[1]) && !empty($match[1])) {
                    $number = (float)$match[1];
                    // សារ​ដែល​មាន $ គឺ​មក​ពី ABA
                    $type = 'ABA'; 
                } 
                // ពិនិត្យ​មើល​ថា​តើ​វា​ត្រូវ​នឹង​ទម្រង់ទី២ (Received xx.xx USD) ដែរ​ឬទេ
                elseif (isset($match[2]) && !empty($match[2])) {
                    $number = (float)$match[2];
                    // សារ​ដែល​មាន "Received" អាច​ជា AC ឬ​ប្រភព​ផ្សេង
                    $type = 'AC';
                }

                if ($number > 0 && $type) {
                    $chat_data[] = ['value' => $number, 'datetime' => date('Y-m-d H:i:s'), 'type' => $type];
                }
            }
            
            $all_data[$chat_id] = $chat_data;
            if (!writeData($all_data)) { sendMessage($chat_id, '❌ មានបញ្ហាក្នុងការរក្សាទុកទិន្នន័យ។'); }
        }
        // --- [END OF MODIFIED BLOCK] ---
    }
} elseif (isset($update['callback_query'])) {
    $callback_query = $update['callback_query'];
    $callback_id = $callback_query['id'];
    $chat_id = $callback_query['message']['chat']['id'];
    $message_id = $callback_query['message']['message_id'];
    $data = $callback_query['data'];
    answerCallbackQuery($callback_id);

    if ($data === 'show_calendar') {
        $calendar = generateCalendar(date('Y'), date('m'));
        editMessageText($chat_id, $message_id, "🗓️ សូមជ្រើសរើសកាលបរិច្ឆេទសម្រាប់មើលរបាយការណ៍៖", 'HTML', $calendar);
    } elseif ($data === 'back_to_report_menu') {
        $report_menu_keyboard = ['inline_keyboard' => [[['text' => '✅ ថ្ងៃនេះ (' . date('d M') . ')', 'callback_data' => 'select_date_today']], [['text' => '⏪ ម្សិលមិញ', 'callback_data' => 'select_date_yesterday']], [['text' => '📅 ជ្រើសរើសថ្ងៃពីប្រតិទិន', 'callback_data' => 'show_calendar']]]];
        editMessageText($chat_id, $message_id, "📋 សូមជ្រើសរើសរបាយការណ៍ដែលអ្នកចង់មើល៖", 'HTML', $report_menu_keyboard);
    } elseif (strpos($data, 'nav_') === 0) {
        $parts = explode('-', substr($data, 4));
        $calendar = generateCalendar((int)$parts[0], (int)$parts[1]);
        editMessageText($chat_id, $message_id, "🗓️ សូមជ្រើសរើសកាលបរិច្ឆេទសម្រាប់មើលរបាយការណ៍៖", 'HTML', $calendar);
    
    } elseif (strpos($data, 'select_date_') === 0) {
        $target_date = '';
        if ($data === 'select_date_today') { $target_date = date('Y-m-d'); } 
        elseif ($data === 'select_date_yesterday') { $target_date = date('Y-m-d', strtotime('yesterday')); } 
        else { $target_date = substr($data, 12); }
        
        $formatted_date = date("d F Y", strtotime($target_date));
        $text = "អ្នកបានជ្រើសរើសថ្ងៃទី: <b>$formatted_date</b>\n\nតើអ្នកចង់មើលរបាយការណ៍ប្រភេទណា?";
        
        // បង្កើត Keyboard សម្រាប់ជ្រើសរើសប្រភេទ
        $type_filter_keyboard = ['inline_keyboard' => [
            [['text' => '📊 មើលទាំងអស់', 'callback_data' => 'filter_all_' . $target_date]],
            [['text' => '=> មើលតែ AC', 'callback_data' => 'filter_ac_' . $target_date]],
            [['text' => '=> មើលតែ ABA', 'callback_data' => 'filter_aba_' . $target_date]],
            [['text' => '↩️ ត្រឡប់ក្រោយ', 'callback_data' => 'back_to_report_menu']]
        ]];

        editMessageText($chat_id, $message_id, $text, 'HTML', $type_filter_keyboard);
    
    } elseif (strpos($data, 'filter_') === 0) {
        // បំបែក callback data ដើម្បីទទួលបានប្រភេទ និងកាលបរិច្ឆេទ (e.g., 'filter_ac_2023-10-26')
        list(, $filter_type, $target_date) = explode('_', $data, 3);
        
        $all_data = readData();
        $chat_data = isset($all_data[$chat_id]) && is_array($all_data[$chat_id]) ? $all_data[$chat_id] : [];
        $total_usd = 0;
        $entries_for_date = [];
        
        foreach ($chat_data as $entry) {
            if (!is_array($entry) || !isset($entry['value'])) { continue; }
            $entry_date_to_check = isset($entry['datetime']) ? substr($entry['datetime'], 0, 10) : (isset($entry['date']) ? $entry['date'] : null);
            
            if ($entry_date_to_check === $target_date) {
                $type_matches = false;
                if ($filter_type === 'all') {
                    $type_matches = true;
                } elseif ($filter_type === 'ac' && isset($entry['type']) && strtoupper($entry['type']) === 'AC') {
                    $type_matches = true;
                } elseif ($filter_type === 'aba' && isset($entry['type']) && strtoupper($entry['type']) === 'ABA') {
                    $type_matches = true;
                }
                
                if ($type_matches) {
                    $entries_for_date[] = $entry;
                    $total_usd += (float) $entry['value'];
                }
            }
        }

        $formatted_date = date("d F Y", strtotime($target_date));
        $report_type_label = ($filter_type === 'all') ? " (ទាំងអស់)" : " (តែ " . strtoupper($filter_type) . ")";

        if (empty($entries_for_date)) {
            $response = "📅 <b>របាយការណ៍សម្រាប់ថ្ងៃទី $formatted_date" . $report_type_label . "</b>\n\n";
            $response .= "<i>មិនមានទិន្នន័យសម្រាប់ប្រភេទនេះទេ។</i>";
        } else {
            $response  = "📅 <b>របាយការណ៍ប្រចាំថ្ងៃ" . $report_type_label . "</b>\n\n";
            $response .= "📆 ថ្ងៃទី: <b>$formatted_date</b>\n";
            $response .= "━━━━━━━━━━━━━━━━\n\n";
            $response .= "<b>📋 បញ្ជីប្រតិបត្តិការ:</b>\n";

            $i = 1;
            foreach ($entries_for_date as $entry) {
                $time_display = isset($entry['datetime']) ? date('h:i A', strtotime($entry['datetime'])) : "---";
                $value_display = number_format($entry['value'], 2);
                $type_display = isset($entry['type']) ? " ({$entry['type']})" : "";
                $response .= sprintf(" \n  %02d. 🕓 %s  ➜  💵 <b>%s USD</b>%s\n", $i, $time_display, $value_display, $type_display);
                $i++;
            }

            $response .= "\n━━━━━━━━━━━━━━━━\n";
            $response .= "📦 <b>សរុបប្រចាំថ្ងៃ</b>\n";
            $response .= " \n  • ចំនួនប្រតិបត្តិការ៖ <b>" . count($entries_for_date) . "</b> ដង\n";
            $response .= "   • 💵 USD: <b>" . number_format($total_usd, 2) . "</b>\n";
            $response .= "   • 💰 KHR: <b>" . number_format($total_usd * USD_TO_KHR_RATE, 0) . " ៛</b>\n";
            $response .= "━━━━━━━━━━━━━━━━\n";
            $response .= "🧾 <i>ទិន្នន័យត្រឹមពេល " . date('h:i A') . "</i>";
        }
        
        $back_button = ['inline_keyboard' => [[['text' => '↩️ ត្រឡប់ទៅម៉ឺនុយរបាយការណ៍', 'callback_data' => 'back_to_report_menu']]]];
        editMessageText($chat_id, $message_id, $response, 'HTML', $back_button);
    }
}
?>