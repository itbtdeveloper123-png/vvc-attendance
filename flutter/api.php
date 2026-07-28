<?php
/**
 * VVC-HRM API Gateway — flutter/ folder redirect
 *
 * flutter/api.php is a LEGACY location kept for backward-compatibility.
 * The canonical, up-to-date API is located at the project root: ../api.php
 *
 * This file simply forwards every request to the root api.php so that:
 *   - Mobile app calls to https://app.vvc.asia/flutter/api.php keep working
 *   - All bug-fixes & new features need only be maintained in one place (root api.php)
 *   - No more "copy gets out of sync" maintenance nightmare
 *
 * HOW IT WORKS:
 *   PHP include() shares the same request context ($_GET, $_POST, $_SERVER, headers)
 *   so the root api.php receives the full original request transparently.
 */

// Point all require_once / __DIR__ references inside root api.php
// to the project root, not the flutter/ sub-directory.
chdir(__DIR__ . '/..');          // Change working dir to project root
require_once __DIR__ . '/../api.php';   // Execute root api.php in-place
