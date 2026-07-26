<?php
// Form Import Helper - Convert existing Flutter forms to Form Builder templates
// This script helps map existing form screens to Form Builder format

header('Content-Type: text/html; charset=UTF-8');
ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/config.php';

echo "<h2>Flutter Form to Form Builder Template Converter</h2>";
echo "<style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .success { color: green; font-weight: bold; }
    .info { color: blue; }
    .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    code { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }
    pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
    .field-mapping { margin: 10px 0; padding: 10px; background: #f9f9f9; border-left: 3px solid #667eea; }
</style>";

$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_error) {
    die("Database connection failed: " . $mysqli->connect_error);
}

// Existing Flutter Forms Analysis
$existingForms = [
    'leave_request' => [
        'name' => 'សំណើសុំច្បាប់ឈប់សម្រាក (Leave Request)',
        'description' => 'សំណើសុំច្បាប់ឈប់សម្រាកប្រចាំឆ្នាំ, ជំងឺ, មាតុភាព',
        'category' => 'request',
        'fields' => [
            [
                'field_type' => 'text',
                'field_name' => 'requester_name',
                'field_label' => 'ឈ្មោះអ្នកស្នើសុំ',
                'placeholder' => '',
                'required' => true,
                'display_order' => 1
            ],
            [
                'field_type' => 'email',
                'field_name' => 'email',
                'field_label' => 'អ៊ីមែល',
                'placeholder' => 'email@vvc.com',
                'required' => true,
                'display_order' => 2
            ],
            [
                'field_type' => 'department',
                'field_name' => 'department',
                'field_label' => 'ផ្នែក/មុខតំណែង',
                'placeholder' => '',
                'required' => true,
                'display_order' => 3
            ],
            [
                'field_type' => 'position',
                'field_name' => 'position',
                'field_label' => 'មុខតំណែង',
                'placeholder' => '',
                'required' => true,
                'display_order' => 4
            ],
            [
                'field_type' => 'branch',
                'field_name' => 'branch',
                'field_label' => 'សាខា',
                'placeholder' => '',
                'required' => true,
                'display_order' => 5
            ],
            [
                'field_type' => 'date',
                'field_name' => 'request_date',
                'field_label' => 'ថ្ងៃខែឆ្នាំសុំឈប់',
                'placeholder' => '',
                'required' => true,
                'display_order' => 6
            ],
            [
                'field_type' => 'date',
                'field_name' => 'return_date',
                'field_label' => 'ថ្ងៃចូលធ្វើការវិញ',
                'placeholder' => '',
                'required' => true,
                'display_order' => 7
            ],
            [
                'field_type' => 'number',
                'field_name' => 'number_of_days',
                'field_label' => 'ចំនួនថ្ងៃ',
                'placeholder' => '1',
                'required' => true,
                'display_order' => 8
            ],
            [
                'field_type' => 'textarea',
                'field_name' => 'reason',
                'field_label' => 'មូលហេតុ',
                'placeholder' => 'សូមបញ្ជាក់មូលហេតុ...',
                'required' => true,
                'display_order' => 9
            ],
            [
                'field_type' => 'text',
                'field_name' => 'location',
                'field_label' => 'ទីកន្លែងអំឡុងពេលឈប់',
                'placeholder' => '',
                'required' => false,
                'display_order' => 10
            ],
            [
                'field_type' => 'text',
                'field_name' => 'contact_number',
                'field_label' => 'ទំនាក់ទំនងបន្ទាន់',
                'placeholder' => '',
                'required' => true,
                'display_order' => 11
            ],
            [
                'field_type' => 'text',
                'field_name' => 'assigned_to',
                'field_label' => 'ប្រគល់ការងារឱ្យ',
                'placeholder' => '',
                'required' => false,
                'display_order' => 12
            ],
            [
                'field_type' => 'signature',
                'field_name' => 'signature',
                'field_label' => 'ហត្ថលេខាអ្នកស្នើសុំ',
                'placeholder' => '',
                'required' => true,
                'display_order' => 13
            ]
        ]
    ],
    'ot_request' => [
        'name' => 'សំណើសុំថែមម៉ោង (OT Request)',
        'description' => 'សំណើសុំធ្វើការថែមម៉ោង',
        'category' => 'request',
        'fields' => [
            [
                'field_type' => 'text',
                'field_name' => 'requester_name',
                'field_label' => 'ឈ្មោះអ្នកស្នើសុំ',
                'placeholder' => '',
                'required' => true,
                'display_order' => 1
            ],
            [
                'field_type' => 'date',
                'field_name' => 'ot_date',
                'field_label' => 'ថ្ងៃធ្វើការ OT',
                'placeholder' => '',
                'required' => true,
                'display_order' => 2
            ],
            [
                'field_type' => 'time',
                'field_name' => 'start_time',
                'field_label' => 'ម៉ោងចាប់ផ្តាល់',
                'placeholder' => '',
                'required' => true,
                'display_order' => 3
            ],
            [
                'field_type' => 'time',
                'field_name' => 'end_time',
                'field_label' => 'ម៉ោងបញ្ចប់',
                'placeholder' => '',
                'required' => true,
                'display_order' => 4
            ],
            [
                'field_type' => 'number',
                'field_name' => 'total_hours',
                'field_label' => 'ចំនួនម៉ោង',
                'placeholder' => '',
                'required' => true,
                'display_order' => 5
            ],
            [
                'field_type' => 'textarea',
                'field_name' => 'reason',
                'field_label' => 'មូលហេតុ',
                'placeholder' => 'សូមបញ្ជាក់មូលហេតុ...',
                'required' => true,
                'display_order' => 6
            ],
            [
                'field_type' => 'signature',
                'field_name' => 'signature',
                'field_label' => 'ហត្ថលេខាអ្នកស្នើសុំ',
                'placeholder' => '',
                'required' => true,
                'display_order' => 7
            ]
        ]
    ],
    'late_request' => [
        'name' => 'សំណើសុំមកយឺត (Late Request)',
        'description' => 'សំណើសុំមកយឺតការងារ',
        'category' => 'request',
        'fields' => [
            [
                'field_type' => 'text',
                'field_name' => 'requester_name',
                'field_label' => 'ឈ្មោះអ្នកស្នើសុំ',
                'placeholder' => '',
                'required' => true,
                'display_order' => 1
            ],
            [
                'field_type' => 'date',
                'field_name' => 'late_date',
                'field_label' => 'ថ្ងៃមកយឺត',
                'placeholder' => '',
                'required' => true,
                'display_order' => 2
            ],
            [
                'field_type' => 'time',
                'field_name' => 'late_time',
                'field_label' => 'ម៉ោងមកយឺត',
                'placeholder' => '',
                'required' => true,
                'display_order' => 3
            ],
            [
                'field_type' => 'number',
                'field_name' => 'late_minutes',
                'field_label' => 'នាទីយឺត',
                'placeholder' => '',
                'required' => true,
                'display_order' => 4
            ],
            [
                'field_type' => 'textarea',
                'field_name' => 'reason',
                'field_label' => 'មូលហេតុ',
                'placeholder' => 'សូមបញ្ជាក់មូលហេតុ...',
                'required' => true,
                'display_order' => 5
            ],
            [
                'field_type' => 'signature',
                'field_name' => 'signature',
                'field_label' => 'ហត្ថលេខាអ្នកស្នើសុំ',
                'placeholder' => '',
                'required' => true,
                'display_order' => 6
            ]
        ]
    ]
];

// Function to import form as template
function importFormAsTemplate($mysqli, $formKey) {
    global $existingForms;
    
    if (!isset($existingForms[$formKey])) {
        return ['success' => false, 'message' => 'Form not found'];
    }
    
    $form = $existingForms[$formKey];
    
    // Check if template already exists
    $check = $mysqli->prepare("SELECT id FROM form_templates WHERE name = ?");
    $check->bind_param("s", $form['name']);
    $check->execute();
    $result = $check->get_result();
    
    if ($result->num_rows > 0) {
        return ['success' => false, 'message' => 'Template already exists'];
    }
    
    // Insert template
    $stmt = $mysqli->prepare("INSERT INTO form_templates (name, description, category, status) VALUES (?, ?, ?, 'active')");
    $stmt->bind_param("sss", $form['name'], $form['description'], $form['category']);
    
    if (!$stmt->execute()) {
        return ['success' => false, 'message' => 'Failed to create template: ' . $mysqli->error];
    }
    
    $templateId = $mysqli->insert_id;
    
    // Insert fields
    foreach ($form['fields'] as $field) {
        $fieldStmt = $mysqli->prepare("INSERT INTO form_fields (template_id, field_type, field_name, field_label, placeholder, required, display_order) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $fieldStmt->bind_param("isssisi", 
            $templateId, 
            $field['field_type'], 
            $field['field_name'], 
            $field['field_label'], 
            $field['placeholder'], 
            $field['required'], 
            $field['display_order']
        );
        
        if (!$fieldStmt->execute()) {
            return ['success' => false, 'message' => 'Failed to create field: ' . $mysqli->error];
        }
    }
    
    return ['success' => true, 'template_id' => $templateId, 'message' => 'Template imported successfully'];
}

// Handle import request
if (isset($_GET['import']) || isset($_POST['import_form'])) {
    $formKey = $_GET['import'] ?? $_POST['form_key'] ?? '';
    $result = importFormAsTemplate($mysqli, $formKey);
    
    if ($result['success']) {
        echo "<div class='success'>✅ {$result['message']} (Template ID: {$result['template_id']})</div>";
        echo "<div class='info'>ℹ️ You can now edit this template in <a href='form_builder.php'>Form Builder</a></div>";
        echo "<div class='info'>ℹ️ <a href='form_builder.php'>Click here to go to Form Builder</a></div>";
    } else {
        echo "<div class='error'>❌ {$result['message']}</div>";
    }
}

// Display available forms
echo "<div class='section'>";
echo "<h3>Available Flutter Forms to Import</h3>";

foreach ($existingForms as $key => $form) {
    echo "<div class='field-mapping'>";
    echo "<h4>{$form['name']}</h4>";
    echo "<p><strong>Description:</strong> {$form['description']}</p>";
    echo "<p><strong>Category:</strong> {$form['category']}</p>";
    echo "<p><strong>Fields:</strong> " . count($form['fields']) . " fields</p>";
    
    echo "<form method='POST'>";
    echo "<input type='hidden' name='import_form' value='1'>";
    echo "<input type='hidden' name='form_key' value='{$key}'>";
    echo "<button type='submit' style='background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;'>Import as Template</button>";
    echo "</form>";
    
    echo "</div>";
}
echo "</div>";

// Display field mappings
echo "<div class='section'>";
echo "<h3>Field Mappings Preview</h3>";

foreach ($existingForms as $key => $form) {
    echo "<h4>{$form['name']} - Field Structure</h4>";
    echo "<pre>";
    echo json_encode($form['fields'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    echo "</pre>";
}
echo "</div>";

$mysqli->close();
?>
