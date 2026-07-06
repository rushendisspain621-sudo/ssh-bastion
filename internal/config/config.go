package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// BastionConfig 堡垒机代理服务配置
type BastionConfig struct {
	ListenAddr  string `yaml:"listen_addr"`  // SSH 监听地址，例如 "0.0.0.0:2222"
	HostKey     string `yaml:"host_key"`     // SSH 主机私钥文件路径
	AuditAddr   string `yaml:"audit_addr"`   // 审计服务 gRPC 地址，例如 "localhost:50051"
	BastionPass string `yaml:"bastion_pass"` // 堡垒机统一登录密码
}

// AuditConfig 审计服务配置
type AuditConfig struct {
	ListenAddr string            `yaml:"listen_addr"` // gRPC 监听地址
	Blacklist  []string          `yaml:"blacklist"`   // 黑名单命令列表
	Passwords  map[string]string `yaml:"passwords"`   // 目标主机密码映射 (IP -> 密码)
}

// LoadBastionConfig 从指定路径加载并解析堡垒机配置
func LoadBastionConfig(path string) (*BastionConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg BastionConfig
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}

// LoadAuditConfig 从指定路径加载并解析审计服务配置
func LoadAuditConfig(path string) (*AuditConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg AuditConfig
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}
