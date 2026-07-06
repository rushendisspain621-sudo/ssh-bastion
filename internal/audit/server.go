package audit

import (
	"context"
	"fmt"
	"strings"

	pb "ssh-bastion/proto"
)

// Server 审计服务实现结构体
// 负责：命令审计、黑名单拦截、密码提供
type Server struct {
	pb.UnimplementedAuditServer // 嵌入未实现接口，满足 gRPC 接口要求

	Blacklist []string          // 黑名单命令列表（如 rm -rf / 等）
	Passwords map[string]string // 模拟后端数据库：IP -> 密码
}

// CheckCommand 检查命令是否合法（核心拦截逻辑）
func (s *Server) CheckCommand(ctx context.Context, req *pb.CommandRequest) (*pb.CommandResponse, error) {
	cmdStr := strings.TrimSpace(req.Command) // 去除前后空格，防止绕过检测

	// 遍历黑名单，若包含关键字则拒绝执行
	for _, bad := range s.Blacklist {
		if strings.Contains(cmdStr, bad) {
			return &pb.CommandResponse{
				Allowed: false,
				Reason:  fmt.Sprintf("\r\n[Security Alert] Command '%s' is prohibited!\r\n", bad),
			}, nil
		}
	}

	// 不在黑名单中，允许执行
	return &pb.CommandResponse{Allowed: true}, nil
}

// LogCommand 记录用户执行的命令（审计日志）
func (s *Server) LogCommand(ctx context.Context, req *pb.LogRequest) (*pb.Empty, error) {
	fmt.Printf("[AUDIT LOG] User: %s | Command: %s\n", req.User, req.Command)
	return &pb.Empty{}, nil
}

// GetBackendCredentials 根据目标 IP 返回对应的登录密码
func (s *Server) GetBackendCredentials(ctx context.Context, req *pb.CredentialRequest) (*pb.CredentialResponse, error) {
	pass, exists := s.Passwords[req.TargetIp]
	if !exists {
		return nil, fmt.Errorf("no credentials found for IP: %s", req.TargetIp)
	}
	return &pb.CredentialResponse{Password: pass}, nil
}
