<?php
$request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if (strpos($request_uri, '/api/admin/') !== false) {
    require_once 'api/admin/admin_features.php';
} 
else {
    http_response_code(404);
    echo json_encode(['status' => 'error', 'message' => 'Route not found']);
}
?>