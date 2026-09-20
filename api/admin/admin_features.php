<?php
header('Content-Type: application/json');
session_start();

require_once '../../config/database.php';

function checkAdminAccess() {
    if (!isset($_SESSION['user_id']) || $_SESSION['user_role'] !== 'ADMIN') {
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
        exit;
    }
}

function logAudit($user_id, $action, $table, $record_id, $ip) {
    global $pdo;
    $stmt = $pdo->prepare("
        INSERT INTO audit_logs (user_id, action_name, target_table, record_id, ip_address) 
        VALUES (?, ?, ?, ?, ?)
    ");
    $stmt->execute([$user_id, $action, $table, $record_id, $ip]);
}

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$ip = $_SERVER['REMOTE_ADDR'];

if (strpos($path, 'provision-account') !== false && $method === 'POST') {
    checkAdminAccess();
    $data = json_decode(file_get_contents("php://input"), true);
    
    try {
        $email_check = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
        $email_check->execute([$data['email']]);
        
        if ($email_check->fetchColumn() > 0) {
            echo json_encode(['status' => 'error', 'message' => 'Email already exists']);
            exit;
        }
        
        $password_hash = password_hash($data['password'], PASSWORD_BCRYPT);
        
        $stmt = $pdo->prepare("
            INSERT INTO users (role_id, full_name, email, phone_number, password_hash, is_verified) 
            VALUES (?, ?, ?, ?, ?, 1)
        ");
        
        $stmt->execute([
            $data['role_id'],
            $data['full_name'],
            $data['email'],
            $data['phone_number'],
            $password_hash
        ]);
        
        $user_id = $pdo->lastInsertId();
        logAudit($_SESSION['user_id'], 'PROVISION_ACCOUNT', 'users', $user_id, $ip);
        
        echo json_encode([
            'status' => 'success',
            'message' => 'Account created successfully',
            'user_id' => $user_id
        ]);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
}

else if (strpos($path, 'change-role') !== false && $method === 'PUT') {
    checkAdminAccess();
    $data = json_decode(file_get_contents("php://input"), true);
    
    try {
        $check = $pdo->prepare("SELECT role_id FROM users WHERE user_id = ?");
        $check->execute([$data['user_id']]);
        $old_role = $check->fetchColumn();
        
        if (!$old_role) {
            echo json_encode(['status' => 'error', 'message' => 'User not found']);
            exit;
        }
        
        $stmt = $pdo->prepare("UPDATE users SET role_id = ? WHERE user_id = ?");
        $stmt->execute([$data['role_id'], $data['user_id']]);
        
        logAudit($_SESSION['user_id'], 'CHANGE_ROLE', 'users', $data['user_id'], $ip);
        
        echo json_encode([
            'status' => 'success',
            'message' => 'Role updated successfully',
            'old_role_id' => $old_role,
            'new_role_id' => $data['role_id']
        ]);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
}

else if (strpos($path, 'audit-logs') !== false && $method === 'GET') {
    checkAdminAccess();
    
    try {
        $user_id = $_GET['user_id'] ?? null;
        $action = $_GET['action'] ?? null;
        $table = $_GET['table'] ?? null;
        $days = $_GET['days'] ?? 30;
        $limit = $_GET['limit'] ?? 100;
        
        $query = "
            SELECT al.*, u.full_name, u.email 
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.user_id
            WHERE al.logged_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
        ";
        $params = [$days];
        
        if ($user_id) {
            $query .= " AND al.user_id = ?";
            $params[] = $user_id;
        }
        
        if ($action) {
            $query .= " AND al.action_name LIKE ?";
            $params[] = "%$action%";
        }
        
        if ($table) {
            $query .= " AND al.target_table = ?";
            $params[] = $table;
        }
        
        $query .= " ORDER BY al.logged_at DESC LIMIT ?";
        $params[] = $limit;
        
        $stmt = $pdo->prepare($query);
        $stmt->execute($params);
        $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode([
            'status' => 'success',
            'total' => count($logs),
            'data' => $logs
        ]);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
}

else if (strpos($path, 'backup-database') !== false && $method === 'POST') {
    checkAdminAccess();
    
    try {
        $backup_dir = __DIR__ . '/../../backups/';
        
        if (!is_dir($backup_dir)) {
            mkdir($backup_dir, 0755, true);
        }
        
        $timestamp = date('Y-m-d_H-i-s');
        $backup_file = 'backup_' . $timestamp . '.sql';
        $backup_path = $backup_dir . $backup_file;
        
        $db_host = getenv('DB_HOST');
        $db_user = getenv('DB_USER');
        $db_pass = getenv('DB_PASS');
        $db_name = getenv('DB_NAME');
        
        $command = "mysqldump --single-transaction --quick --lock-tables=false -h " . 
                   escapeshellarg($db_host) . " -u " . escapeshellarg($db_user) . 
                   " -p" . escapeshellarg($db_pass) . " " . escapeshellarg($db_name) . 
                   " > " . escapeshellarg($backup_path) . " 2>&1";
        
        exec($command, $output, $return_code);
        
        if ($return_code !== 0) {
            echo json_encode(['status' => 'error', 'message' => 'Backup failed']);
            exit;
        }
        
        if (!file_exists($backup_path)) {
            echo json_encode(['status' => 'error', 'message' => 'Backup file not created']);
            exit;
        }
        
        $file_size = filesize($backup_path);
        
        $stmt = $pdo->prepare("
            INSERT INTO system_backups (file_name, file_size_bytes, created_by, status) 
            VALUES (?, ?, ?, 'COMPLETED')
        ");
        
        $stmt->execute([$backup_file, $file_size, $_SESSION['user_id']]);
        
        logAudit($_SESSION['user_id'], 'DATABASE_BACKUP', 'system_backups', $pdo->lastInsertId(), $ip);
        
        echo json_encode([
            'status' => 'success',
            'message' => 'Backup completed',
            'file_name' => $backup_file,
            'file_size_mb' => round($file_size / 1024 / 1024, 2),
            'timestamp' => $timestamp
        ]);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
}

else if (strpos($path, 'verify-owner') !== false && $method === 'PUT') {
    checkAdminAccess();
    $data = json_decode(file_get_contents("php://input"), true);
    
    try {
        $check = $pdo->prepare("SELECT status FROM owner_verifications WHERE verification_id = ?");
        $check->execute([$data['verification_id']]);
        $current_status = $check->fetchColumn();
        
        if (!$current_status) {
            echo json_encode(['status' => 'error', 'message' => 'Verification not found']);
            exit;
        }
        
        $stmt = $pdo->prepare("
            UPDATE owner_verifications 
            SET status = ?, approved_by = ?, verified_at = NOW() 
            WHERE verification_id = ?
        ");
        
        $stmt->execute([
            $data['status'],
            $_SESSION['user_id'],
            $data['verification_id']
        ]);
        
        logAudit($_SESSION['user_id'], 'VERIFY_OWNER_' . strtoupper($data['status']), 'owner_verifications', $data['verification_id'], $ip);
        
        echo json_encode([
            'status' => 'success',
            'message' => 'Owner verification updated',
            'verification_id' => $data['verification_id'],
            'new_status' => $data['status']
        ]);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
}

else if (strpos($path, 'get-backups') !== false && $method === 'GET') {
    checkAdminAccess();
    
    try {
        $limit = $_GET['limit'] ?? 20;
        
        $stmt = $pdo->prepare("
            SELECT sb.*, u.full_name 
            FROM system_backups sb
            LEFT JOIN users u ON sb.created_by = u.user_id
            ORDER BY sb.created_at DESC
            LIMIT ?
        ");
        
        $stmt->execute([$limit]);
        $backups = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode([
            'status' => 'success',
            'total' => count($backups),
            'data' => $backups
        ]);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
}

else if (strpos($path, 'get-pending-verifications') !== false && $method === 'GET') {
    checkAdminAccess();
    
    try {
        $stmt = $pdo->prepare("
            SELECT ov.*, u.full_name, u.email, f.building_block, f.flat_number
            FROM owner_verifications ov
            JOIN users u ON ov.owner_id = u.user_id
            LEFT JOIN flats f ON u.user_id = f.owner_id
            WHERE ov.status = 'PENDING'
            ORDER BY ov.created_at ASC
        ");
        
        $stmt->execute();
        $verifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode([
            'status' => 'success',
            'total' => count($verifications),
            'data' => $verifications
        ]);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
}

else if (strpos($path, 'system-health') !== false && $method === 'GET') {
    checkAdminAccess();
    
    try {
        $total_users = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
        $total_flats = $pdo->query("SELECT COUNT(*) FROM flats")->fetchColumn();
        $pending_complaints = $pdo->query("SELECT COUNT(*) FROM maintenance_complaints WHERE status = 'PENDING'")->fetchColumn();
        $unpaid_invoices = $pdo->query("SELECT COUNT(*) FROM invoices WHERE status = 'UNPAID'")->fetchColumn();
        $pending_verifications = $pdo->query("SELECT COUNT(*) FROM owner_verifications WHERE status = 'PENDING'")->fetchColumn();
        
        $backup_query = $pdo->query("SELECT file_size_bytes, created_at FROM system_backups ORDER BY created_at DESC LIMIT 1");
        $last_backup = $backup_query->fetch(PDO::FETCH_ASSOC);
        
        echo json_encode([
            'status' => 'success',
            'system_health' => [
                'total_users' => $total_users,
                'total_flats' => $total_flats,
                'pending_complaints' => $pending_complaints,
                'unpaid_invoices' => $unpaid_invoices,
                'pending_owner_verifications' => $pending_verifications,
                'last_backup' => $last_backup ? [
                    'date' => $last_backup['created_at'],
                    'size_mb' => round($last_backup['file_size_bytes'] / 1024 / 1024, 2)
                ] : null
            ]
        ]);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
}

else {
    http_response_code(404);
    echo json_encode(['status' => 'error', 'message' => 'Endpoint not found']);
}
?>