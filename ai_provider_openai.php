<?php

if (!function_exists('ai_chat_resolve_provider_config')) {
    function ai_chat_resolve_provider_config()
    {
        $preferred = strtolower(trim((string)(defined('AI_CHAT_PROVIDER') ? AI_CHAT_PROVIDER : '')));
        $openAiKey = trim((string)(defined('OPENAI_API_KEY') ? OPENAI_API_KEY : ''));
        $groqKey = trim((string)(defined('GROQ_API_KEY') ? GROQ_API_KEY : ''));
        $modelOverride = trim((string)(defined('AI_CHAT_MODEL') ? AI_CHAT_MODEL : ''));
        $reasoningEffort = strtolower(trim((string)(defined('AI_CHAT_REASONING_EFFORT') ? AI_CHAT_REASONING_EFFORT : '')));

        if ($preferred === 'openai' && $openAiKey !== '') {
            return [
                'provider' => 'openai',
                'endpoint' => 'https://api.openai.com/v1/chat/completions',
                'api_key' => $openAiKey,
                'model' => $modelOverride !== '' ? $modelOverride : 'gpt-4o-mini',
                'reasoning_effort' => $reasoningEffort,
            ];
        }

        if ($preferred === 'groq' && $groqKey !== '') {
            return [
                'provider' => 'groq',
                'endpoint' => 'https://api.groq.com/openai/v1/chat/completions',
                'api_key' => $groqKey,
                'model' => $modelOverride !== '' ? $modelOverride : 'llama-3.3-70b-versatile',
                'reasoning_effort' => $reasoningEffort,
            ];
        }

        if ($openAiKey !== '') {
            return [
                'provider' => 'openai',
                'endpoint' => 'https://api.openai.com/v1/chat/completions',
                'api_key' => $openAiKey,
                'model' => $modelOverride !== '' ? $modelOverride : 'gpt-4o-mini',
                'reasoning_effort' => $reasoningEffort,
            ];
        }

        if ($groqKey !== '') {
            return [
                'provider' => 'groq',
                'endpoint' => 'https://api.groq.com/openai/v1/chat/completions',
                'api_key' => $groqKey,
                'model' => $modelOverride !== '' ? $modelOverride : 'llama-3.3-70b-versatile',
                'reasoning_effort' => $reasoningEffort,
            ];
        }

        return null;
    }
}

if (!function_exists('ai_chat_http_post_json')) {
    function ai_chat_http_post_json($url, array $payload, array $headers = [])
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge([
            'Content-Type: application/json',
        ], $headers));
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload, JSON_UNESCAPED_UNICODE));
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);
        $response = curl_exec($ch);
        $error = curl_error($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false || $error !== '') {
            return [
                'ok' => false,
                'status' => $status,
                'message' => $error !== '' ? $error : 'Unknown cURL error',
            ];
        }

        $decoded = json_decode($response, true);
        if (!is_array($decoded)) {
            return [
                'ok' => false,
                'status' => $status,
                'message' => 'Invalid JSON response',
                'raw' => $response,
            ];
        }

        if ($status >= 400) {
            $message = $decoded['error']['message'] ?? ('HTTP ' . $status);
            return [
                'ok' => false,
                'status' => $status,
                'message' => $message,
                'raw' => $decoded,
            ];
        }

        return [
            'ok' => true,
            'status' => $status,
            'data' => $decoded,
        ];
    }
}

if (!function_exists('ai_chat_run_provider_loop')) {
    function ai_chat_run_provider_loop(array $messages, array $tools, callable $toolExecutor)
    {
        $config = ai_chat_resolve_provider_config();
        if (!$config) {
            return [
                'success' => false,
                'message' => 'AI provider is not configured.',
                'provider' => 'local',
            ];
        }

        $trace = [];
        $loop = 0;

        while ($loop < 4) {
            $loop++;

            $payload = [
                'model' => $config['model'],
                'messages' => $messages,
                'temperature' => 0.2,
            ];

            $reasoningEffort = strtolower(trim((string)($config['reasoning_effort'] ?? '')));
            $supportsGroqReasoning =
                ($config['provider'] ?? '') === 'groq'
                && in_array((string)($config['model'] ?? ''), ['openai/gpt-oss-20b', 'openai/gpt-oss-120b'], true);
            if ($supportsGroqReasoning && in_array($reasoningEffort, ['low', 'medium', 'high'], true)) {
                $payload['reasoning_effort'] = $reasoningEffort;
                $payload['include_reasoning'] = false;
            }

            if (!empty($tools)) {
                $payload['tools'] = $tools;
                $payload['tool_choice'] = 'auto';
            }

            $res = ai_chat_http_post_json(
                $config['endpoint'],
                $payload,
                ['Authorization: Bearer ' . $config['api_key']]
            );

            if (!$res['ok']) {
                return [
                    'success' => false,
                    'message' => $res['message'] ?? 'Provider request failed.',
                    'provider' => $config['provider'],
                    'model' => $config['model'],
                ];
            }

            $assistant = $res['data']['choices'][0]['message'] ?? null;
            if (!$assistant) {
                return [
                    'success' => false,
                    'message' => 'Provider did not return a valid assistant message.',
                    'provider' => $config['provider'],
                    'model' => $config['model'],
                ];
            }

            $toolCalls = $assistant['tool_calls'] ?? [];
            if (!empty($toolCalls)) {
                $messages[] = $assistant;

                foreach ($toolCalls as $toolCall) {
                    $name = (string)($toolCall['function']['name'] ?? '');
                    $argumentsRaw = (string)($toolCall['function']['arguments'] ?? '{}');
                    $arguments = json_decode($argumentsRaw, true);
                    if (!is_array($arguments)) {
                        $arguments = [];
                    }

                    $toolResult = $toolExecutor($name, $arguments);
                    $trace[] = [
                        'tool' => $name,
                        'arguments' => $arguments,
                        'result' => $toolResult,
                        'ok' => (bool)($toolResult['ok'] ?? false),
                    ];

                    $messages[] = [
                        'role' => 'tool',
                        'tool_call_id' => $toolCall['id'] ?? '',
                        'content' => json_encode($toolResult, JSON_UNESCAPED_UNICODE),
                    ];
                }
                continue;
            }

            return [
                'success' => true,
                'reply' => trim((string)($assistant['content'] ?? '')),
                'tool_trace' => $trace,
                'provider' => $config['provider'],
                'model' => $config['model'],
            ];
        }

        return [
            'success' => false,
            'message' => 'AI tool loop exceeded the maximum allowed turns.',
            'provider' => $config['provider'],
            'model' => $config['model'],
        ];
    }
}
