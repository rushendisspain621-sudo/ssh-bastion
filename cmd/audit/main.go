package main

import (
	"log"
	"net"

	"google.golang.org/grpc"

	"ssh-bastion/internal/audit"
	"ssh-bastion/internal/config"
	pb "ssh-bastion/proto"
)

func main() {
	// 1. 加载审计服务配置
	cfg, err := config.LoadAuditConfig("audit.yaml")
	if err != nil {
		log.Fatalf("Failed to load audit config: %v", err)
	}
	// 2. 创建 TCP 监听器
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	// 3. 创建 gRPC 服务端
	grpcServer := grpc.NewServer()
	// 4. 注册 Audit 服务实现
	pb.RegisterAuditServer(grpcServer, &audit.Server{
		Blacklist: cfg.Blacklist,
	})
	log.Printf("Audit RPC Server listening on %s", cfg.ListenAddr)
	// 5. 启动 gRPC 服务
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
