package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"ssh-bastion/internal/audit"
	"ssh-bastion/internal/config"
	"ssh-bastion/internal/sshproxy"
	pb "ssh-bastion/proto"
)

func main() {
	log.Println("Starting SSH Bastion System...")

	// 1. 启动审计服务
	go startAuditService()
	time.Sleep(1 * time.Second)

	// 2. 启动堡垒机代理服务
	go startBastionService()

	// 3. 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Received shutdown signal. Exiting...")
}

// startAuditService 启动审计 RPC 服务
func startAuditService() {
	cfg, err := config.LoadAuditConfig("audit.yaml")
	if err != nil {
		log.Fatalf("[Audit] Failed to load config: %v", err)
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("[Audit] Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuditServer(grpcServer, &audit.Server{
		Blacklist: cfg.Blacklist,
		Passwords: cfg.Passwords,
	})

	log.Printf("[Audit] RPC Server listening on %s", cfg.ListenAddr)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("[Audit] Failed to serve: %v", err)
	}
}

// startBastionService 启动 SSH 堡垒机服务
func startBastionService() {
	cfg, err := config.LoadBastionConfig("bastion.yaml")
	if err != nil {
		log.Fatalf("[Bastion] Failed to load config: %v", err)
	}

	conn, err := grpc.Dial(cfg.AuditAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("[Bastion] Failed to connect to audit server: %v", err)
	}
	defer conn.Close()

	auditClient := pb.NewAuditClient(conn)
	proxy := &sshproxy.Proxy{
		Config:      cfg,
		AuditClient: auditClient,
	}

	if err := proxy.Start(); err != nil {
		log.Fatalf("[Bastion] Proxy error: %v", err)
	}
}
