package main

import (
	"log"
	"net"

	"ssh-bastion/internal/audit"
	"ssh-bastion/internal/config"
	pb "ssh-bastion/proto"

	"google.golang.org/grpc"
)

func main() {
	// 1. 加载配置 (读取 audit.yaml)
	cfg, err := config.LoadAuditConfig("audit.yaml")
	if err != nil {
		log.Fatalf("Failed to load audit config: %v", err)
	}

	// 2. 创建 TCP 监听器
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// 3. 初始化 gRPC 服务
	grpcServer := grpc.NewServer()

	// 4. 注册审计服务实现 (注入黑名单配置)
	pb.RegisterAuditServer(grpcServer, &audit.Server{
		Blacklist: cfg.Blacklist,
	})

	log.Printf("Audit RPC Server listening on %s", cfg.ListenAddr)

	// 5. 启动服务 (阻塞运行)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
