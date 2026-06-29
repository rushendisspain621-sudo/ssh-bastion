package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// BastionConfig 堡垒机配置结构
type BastionConfig struct {
	ListenAddr  string `yaml:"listen_addr"`  // SSH 监听地址
	HostKey     string `yaml:"host_key"`     // SSH Host Key 文件路径
	AuditAddr   string `yaml:"audit_addr"`   // 审计服务 gRPC 地址
	BastionPass string `yaml:"bastion_pass"` // 堡垒机登录密码
}

// AuditConfig 审计服务配置结构
type AuditConfig struct {
	ListenAddr string            `yaml:"listen_addr"` // gRPC 监听地址
	Blacklist  []string          `yaml:"blacklist"`   // 黑名单命令列表
	Passwords  map[string]string `yaml:"passwords"`   // IP -> 密码映射
}

// LoadBastionConfig 读取堡垒机配置文件
func LoadBastionConfig(path string) (*BastionConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg BastionConfig
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}

// LoadAuditConfig 读取审计服务配置文件
func LoadAuditConfig(path string) (*AuditConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg AuditConfig
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}
