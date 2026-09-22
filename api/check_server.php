<?php
/**
 * Server Capability Checker for PDF-to-Word Microservice
 * Checks if exec(), shell_exec(), proc_open() and Python are available.
 */

header('Content-Type: text/html; charset=utf-8');

function is_func_enabled($func) {
    $disabled = explode(',', ini_get('disable_functions'));
    $disabled = array_map('trim', $disabled);
    return function_exists($func) && !in_array($func, $disabled, true);
}

$execEnabled = is_func_enabled('exec');
$shellExecEnabled = is_func_enabled('shell_exec');
$procOpenEnabled = is_func_enabled('proc_open');

// Test running python command via shell_exec (which is enabled on the server!)
$pythonVersion = 'រកមិនឃើញ';
$pythonCmd = '';
$pdf2docxInstalled = false;

if ($shellExecEnabled) {
    $candidatePaths = [
        'python3',
        '/usr/bin/python3',
        '/usr/local/bin/python3',
        '/bin/python3',
        'python',
    ];

    foreach ($candidatePaths as $cmd) {
        $out = @shell_exec("$cmd --version 2>&1");
        if ($out && strpos(strtolower($out), 'python') !== false) {
            $pythonVersion = trim($out);
            $pythonCmd = $cmd;
            break;
        }
    }

    if (!empty($pythonCmd)) {
        // Test importing pdf2docx with auto-detection of user site-packages (~/.local/lib/python*/site-packages)
        $testScript = 'import sys, os, glob; [sys.path.insert(0, p) for p in glob.glob(os.path.expanduser("~/.local/lib/python*/site-packages")) + glob.glob("/home/*/.local/lib/python*/site-packages")]; import pdf2docx; print("INSTALLED")';
        $testOut = @shell_exec($pythonCmd . ' -c ' . escapeshellarg($testScript) . ' 2>&1');
        $debugTestOut = trim((string)$testOut);
        if ($testOut && strpos($testOut, 'INSTALLED') !== false) {
            $pdf2docxInstalled = true;
        }

        $pipVersion = trim((string)(@shell_exec("$pythonCmd -m pip --version 2>&1") ?: @shell_exec("pip --version 2>&1") ?: 'រកមិនឃើញ'));
    }
}

$disableFunctions = ini_get('disable_functions') ?: 'គ្មាន (អនុញ្ញាតទាំងអស់ - All Allowed)';
$allPassed = $shellExecEnabled && !empty($pythonCmd);
?>
<!DOCTYPE html>
<html lang="km">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ការត្រួតពិនិត្យប្រព័ន្ធ Hosting សម្រាប់ Microservice</title>
    <link href="https://fonts.googleapis.com/css2?family=Kantumruy+Pro:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Kantumruy Pro', sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .card {
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 20px;
            max-width: 650px;
            width: 100%;
            padding: 30px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
        }
        h1 {
            font-size: 20px;
            margin-top: 0;
            color: #38bdf8;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 600;
        }
        .badge-success { background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }
        .badge-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 0;
            border-bottom: 1px solid #334155;
        }
        .item:last-child { border-bottom: none; }
        .label { font-size: 14px; color: #cbd5e1; }
        .subtext { font-size: 11px; color: #94a3b8; margin-top: 3px; }
        .box {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 12px 16px;
            font-family: monospace;
            font-size: 12px;
            color: #f1f5f9;
            margin-top: 15px;
            word-break: break-all;
        }
        .conclusion {
            margin-top: 25px;
            padding: 16px;
            border-radius: 12px;
            font-size: 14px;
            line-height: 1.6;
        }
        .conclusion.pass { background: rgba(34, 197, 94, 0.1); border: 1px solid #22c55e; color: #86efac; }
        .conclusion.fail { background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; color: #fca5a5; }
    </style>
</head>
<body>
    <div class="card">
        <h1>🔍 លទ្ធផលត្រួតពិនិត្យសមត្ថភាព Hosting</h1>
        <p style="color: #94a3b8; font-size: 13px; margin-bottom: 20px;">
            ផ្ទៀងផ្ទាត់ថាតើ Hosting របស់បងអាចដំណើរការ Microservice (Python + PHP) បានឬទេ
        </p>

        <div class="item">
            <div>
                <div class="label">មុខងារ <code>exec()</code> ក្នុង PHP</div>
                <div class="subtext">ចាំបាច់សម្រាប់បញ្ជាឱ្យ Python បម្លែង PDF</div>
            </div>
            <div>
                <?php if ($execEnabled): ?>
                    <span class="status-badge badge-success">✅ អនុញ្ញាត (Enabled)</span>
                <?php else: ?>
                    <span class="status-badge badge-danger">❌ ត្រូវបានបិទ (Disabled)</span>
                <?php endif; ?>
            </div>
        </div>

        <div class="item">
            <div>
                <div class="label">មុខងារ <code>shell_exec()</code> ក្នុង PHP</div>
                <div class="subtext">សម្រាប់ទទួលលទ្ធផល JSON ពី Python Script</div>
            </div>
            <div>
                <?php if ($shellExecEnabled): ?>
                    <span class="status-badge badge-success">✅ អនុញ្ញាត (Enabled)</span>
                <?php else: ?>
                    <span class="status-badge badge-danger">❌ ត្រូវបានបិទ (Disabled)</span>
                <?php endif; ?>
            </div>
        </div>

        <div class="item">
            <div>
                <div class="label">កម្រិត Python ដែលរកឃើញ</div>
                <div class="subtext"><?= htmlspecialchars($pythonCmd ?: 'គ្មាន') ?></div>
            </div>
            <div>
                <span class="status-badge <?= ($pythonVersion !== 'រកមិនឃើញ') ? 'badge-success' : 'badge-danger' ?>">
                    <?= htmlspecialchars($pythonVersion) ?>
                </span>
            </div>
        </div>

        <div class="item">
            <div>
                <div class="label">កញ្ចប់បណ្ណាល័យ <code>pdf2docx</code></div>
                <div class="subtext">ស្នូលសម្រាប់បម្លែង Layout និងរូបភាព</div>
            </div>
            <div>
                <?php if ($pdf2docxInstalled): ?>
                    <span class="status-badge badge-success">✅ បានតម្លើងរួចរាល់ (Installed)</span>
                <?php else: ?>
                    <span class="status-badge badge-danger">⚠️ មិនទាន់តម្លើង (Not Installed)</span>
                <?php endif; ?>
            </div>
        </div>

        <div style="margin-top: 15px;">
            <div class="label">បញ្ជី disable_functions ក្នុង php.ini៖</div>
            <div class="box"><?= htmlspecialchars($disableFunctions) ?></div>
        </div>

        <?php if ($shellExecEnabled && $pdf2docxInstalled): ?>
            <div class="conclusion pass">
                🎉 <strong>អបអរសាទរ! ប្រព័ន្ធរួចរាល់ ១០០%!</strong><br>
                Hosting របស់បងអនុញ្ញាត <code>shell_exec()</code> និងមាន <code>pdf2docx</code> រួចជាស្រេច។ Microservice ដំណើរការបម្លែង PDF to Word បានយ៉ាងរលូន!
            </div>
        <?php elseif ($shellExecEnabled && !empty($pythonCmd)): ?>
            <div class="conclusion pass" style="background: rgba(234, 179, 8, 0.1); border: 1px solid #eab308; color: #fef08a;">
                💡 <strong>សូមដំណើរការ Command នេះក្នុង cPanel Terminal៖</strong><br>
                ដើម្បីធានាថា Package ត្រូវបានដំឡើងត្រូវតាមកំណែ <code><?= htmlspecialchars($pythonVersion) ?></code> សូមវាយបញ្ជាខាងក្រោម៖
                <div class="box" style="background:#1e1b4b; color:#a5b4fc; margin-top:8px;">
                    python3 -m pip install --user pdf2docx python-docx PyMuPDF
                </div>
                <?php if (!empty($debugTestOut)): ?>
                    <div style="margin-top: 10px; font-size: 11px; color: #f87171;">
                        <strong>Debug Error ពី Python៖</strong><br>
                        <pre style="white-space: pre-wrap; word-break: break-all; margin: 4px 0;"><?= htmlspecialchars($debugTestOut) ?></pre>
                    </div>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="conclusion fail">
                ⚠️ <strong>បញ្ជាក់៖</strong> Hosting របស់បងអនុញ្ញាត <code>shell_exec()</code> ប៉ុន្តែរកមិនទាន់ឃើញ Python 3 ឡើយ។ សូមចូលទៅ <strong>Setup Python App</strong> ក្នុង cPanel ដើម្បីបង្កើត Python Environment។
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
