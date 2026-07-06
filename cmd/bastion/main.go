package main

import (
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"ssh-bastion/internal/config"
	"ssh-bastion/internal/sshproxy"
	pb "ssh-bastion/proto"
)

func main() {
	// 1. 加载堡垒机配置 (读取 bastion.yaml)
	cfg, err := config.LoadBastionConfig("bastion.yaml")
	if err != nil {
		log.Fatalf("Failed to load bastion config: %v", err)
	}

	// 2. 连接远程 gRPC 审计服务 (使用非 TLS 连接)
	conn, err := grpc.NewClient(
		cfg.AuditAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect to audit server: %v", err)
	}
	defer conn.Close()

	// 3. 创建 Audit gRPC 客户端
	auditClient := pb.NewAuditClient(conn)

	// 4. 创建 SSH 堡垒机代理对象
	proxy := &sshproxy.Proxy{
		Config:      cfg,
		AuditClient: auditClient,
	}

	// 5. 启动堡垒机服务 (阻塞运行)
	if err := proxy.Start(); err != nil {
		log.Fatalf("Bastion Proxy error: %v", err)
	}
}
