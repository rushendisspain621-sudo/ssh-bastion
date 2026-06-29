package audit

import (
	"context"
	"fmt"
	"strings"

	pb "ssh-bastion/proto"
)

// Server 负责命令审计、黑名单拦截、密码提供
type Server struct {
	pb.UnimplementedAuditServer
	Blacklist []string          // 黑名单命令列表
	Passwords map[string]string // 模拟“后端数据库”：IP -> 密码
}

// 1. 命令检查接口（核心拦截逻辑）
func (s *Server) CheckCommand(ctx context.Context, req *pb.CommandRequest) (*pb.CommandResponse, error) {
	cmdStr := strings.TrimSpace(req.Command)
	for _, bad := range s.Blacklist {
		if strings.Contains(cmdStr, bad) {
			return &pb.CommandResponse{
				Allowed: false,
				Reason:  fmt.Sprintf("\r\n[Security Alert] Command '%s' is prohibited!\r\n", bad),
			}, nil
		}
	}
	return &pb.CommandResponse{Allowed: true}, nil
}

// 2. 命令日志记录接口
func (s *Server) LogCommand(ctx context.Context, req *pb.LogRequest) (*pb.Empty, error) {
	fmt.Printf("[AUDIT LOG] User: %s | Command: %s\n", req.User, req.Command)
	return &pb.Empty{}, nil
}

// 3. 获取后端登录凭证
func (s *Server) GetBackendCredentials(ctx context.Context, req *pb.CredentialRequest) (*pb.CredentialResponse, error) {
	pass, exists := s.Passwords[req.TargetIp]
	if !exists {
		return nil, fmt.Errorf("no credentials found for IP: %s", req.TargetIp)
	}
	return &pb.CredentialResponse{
		Password: pass,
	}, nil
}
