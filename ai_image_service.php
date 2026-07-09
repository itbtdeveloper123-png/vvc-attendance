<?php

if (!function_exists('ai_image_strip_data_uri')) {
    function ai_image_strip_data_uri($base64Image)
    {
        $base64Image = trim((string)$base64Image);
        if (strpos($base64Image, 'data:image') === 0) {
            $base64Image = preg_replace('/^data:image\/[a-zA-Z0-9.+-]+;base64,/', '', $base64Image);
        }
        return preg_replace('/\s+/', '', (string)$base64Image);
    }
}

if (!function_exists('ai_image_extension_for_mime')) {
    function ai_image_extension_for_mime($mime)
    {
        switch (strtolower((string)$mime)) {
            case 'image/png':
                return 'png';
            case 'image/jpeg':
            case 'image/jpg':
                return 'jpg';
            case 'image/webp':
                return 'webp';
            default:
                return '';
        }
    }
}

if (!function_exists('ai_image_safe_employee_fragment')) {
    function ai_image_safe_employee_fragment($employeeId)
    {
        $safe = preg_replace('/[^A-Za-z0-9_-]+/', '', (string)$employeeId);
        return $safe !== '' ? $safe : 'user';
    }
}

if (!function_exists('ai_image_remove_background_to_upload')) {
    function ai_image_remove_background_to_upload($employeeId, $base64Image)
    {
        if (function_exists('set_time_limit')) {
            @set_time_limit(180);
        }

        if (!function_exists('exec')) {
            return [
                'success' => false,
                'message' => 'Server cannot run Node.js because exec() is disabled.',
            ];
        }

        $cleanBase64 = ai_image_strip_data_uri($base64Image);
        if ($cleanBase64 === '') {
            return [
                'success' => false,
                'message' => 'Image data is required.',
            ];
        }

        $imageData = base64_decode($cleanBase64, true);
        if ($imageData === false || $imageData === '') {
            return [
                'success' => false,
                'message' => 'Invalid image data.',
            ];
        }

        $maxBytes = 8 * 1024 * 1024;
        if (strlen($imageData) > $maxBytes) {
            return [
                'success' => false,
                'message' => 'Image is too large. Please choose an image under 8MB.',
            ];
        }

        $info = @getimagesizefromstring($imageData);
        $mime = is_array($info) ? (string)($info['mime'] ?? '') : '';
        $extension = ai_image_extension_for_mime($mime);
        if ($extension === '') {
            return [
                'success' => false,
                'message' => 'Only PNG, JPG, and WEBP images are supported.',
            ];
        }

        $scriptPath = __DIR__ . DIRECTORY_SEPARATOR . 'tools' . DIRECTORY_SEPARATOR . 'remove-bg.mjs';
        if (!is_file($scriptPath)) {
            return [
                'success' => false,
                'message' => 'Background removal script is missing on the server.',
            ];
        }

        $tempDir = sys_get_temp_dir();
        $inputPath = tempnam($tempDir, 'vvc_ai_bg_in_');
        $outputPath = tempnam($tempDir, 'vvc_ai_bg_out_');
        if ($inputPath === false || $outputPath === false) {
            return [
                'success' => false,
                'message' => 'Server could not create temporary image files.',
            ];
        }

        $inputImagePath = $inputPath . '.' . $extension;
        $outputImagePath = $outputPath . '.png';
        @unlink($inputPath);
        @unlink($outputPath);

        if (file_put_contents($inputImagePath, $imageData) === false) {
            @unlink($inputImagePath);
            return [
                'success' => false,
                'message' => 'Server could not write the uploaded image.',
            ];
        }

        $nodeBinary = trim((string)(getenv('NODE_BINARY') ?: 'node'));
        $command = escapeshellarg($nodeBinary) . ' ' .
            escapeshellarg($scriptPath) . ' ' .
            escapeshellarg($inputImagePath) . ' ' .
            escapeshellarg($outputImagePath) . ' 2>&1';

        $output = [];
        $exitCode = 0;
        exec($command, $output, $exitCode);

        @unlink($inputImagePath);

        if ($exitCode !== 0 || !is_file($outputImagePath) || filesize($outputImagePath) <= 0) {
            @unlink($outputImagePath);
            $details = trim(implode("\n", array_slice($output, -8)));
            return [
                'success' => false,
                'message' => 'Background removal failed. Make sure Node.js and @imgly/background-removal-node are installed.',
                'details' => mb_substr($details, 0, 1000, 'UTF-8'),
            ];
        }

        $uploadRelativeDir = 'uploads/ai_backgrounds/';
        $uploadDir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'ai_backgrounds';
        if (!is_dir($uploadDir) && !mkdir($uploadDir, 0755, true)) {
            @unlink($outputImagePath);
            return [
                'success' => false,
                'message' => 'Server could not create the background removal upload directory.',
            ];
        }

        try {
            $random = bin2hex(random_bytes(4));
        } catch (Throwable $e) {
            $random = (string)mt_rand(100000, 999999);
        }

        $fileName = 'ai_bg_' . ai_image_safe_employee_fragment($employeeId) . '_' . time() . '_' . $random . '.png';
        $destinationPath = $uploadDir . DIRECTORY_SEPARATOR . $fileName;
        if (!rename($outputImagePath, $destinationPath)) {
            if (!copy($outputImagePath, $destinationPath)) {
                @unlink($outputImagePath);
                return [
                    'success' => false,
                    'message' => 'Server could not save the background-free PNG.',
                ];
            }
            @unlink($outputImagePath);
        }

        $pngData = file_get_contents($destinationPath);
        if ($pngData === false || $pngData === '') {
            return [
                'success' => false,
                'message' => 'Server saved the PNG but could not read it back.',
            ];
        }

        return [
            'success' => true,
            'image_path' => $uploadRelativeDir . $fileName,
            'image_base64' => base64_encode($pngData),
            'mime_type' => 'image/png',
            'message' => 'Background removed successfully.',
        ];
    }
}
