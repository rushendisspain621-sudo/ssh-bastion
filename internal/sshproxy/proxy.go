package sshproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"ssh-bastion/internal/config"
	pb "ssh-bastion/proto"

	"golang.org/x/crypto/ssh"
)

var activeConnections int32

// Proxy SSH堡垒机核心结构
type Proxy struct {
	Config      *config.BastionConfig
	AuditClient pb.AuditClient
}

// Start 启动SSH堡垒机服务
func (p *Proxy) Start() error {
	log.Printf("[INIT] Bastion password loaded: '%s'", p.Config.BastionPass)

	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			log.Printf("[AUTH] user=%s try password=%s", c.User(), pass)
			if string(pass) == p.Config.BastionPass {
				log.Printf("[AUTH] success user=%s", c.User())
				return nil, nil
			}
			log.Printf("[AUTH] failed user=%s", c.User())
			return nil, fmt.Errorf("authentication failed")
		},
	}

	keyBytes, err := os.ReadFile(p.Config.HostKey)
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return err
	}
	sshConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", p.Config.ListenAddr)
	if err != nil {
		return err
	}
	log.Printf("[START] Bastion listening on %s", p.Config.ListenAddr)

	go func() {
		for {
			time.Sleep(10 * time.Second)
			log.Printf("[STATE] active connections = %d", atomic.LoadInt32(&activeConnections))
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go p.handleConnection(conn, sshConfig)
	}
}

// handleConnection 处理SSH握手
func (p *Proxy) handleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	serverConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("[ERROR] handshake failed: %v", err)
		return
	}
	defer serverConn.Close()
	log.Printf("[INFO] user connected: %s", serverConn.User())

	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "only session allowed")
			continue
		}
		go p.handleSession(ch, serverConn)
	}
}

// handleSession 核心业务逻辑
func (p *Proxy) handleSession(newChannel ssh.NewChannel, clientConn *ssh.ServerConn) {
	atomic.AddInt32(&activeConnections, 1)
	defer atomic.AddInt32(&activeConnections, -1)

	rawUser := clientConn.User()
	parts := strings.SplitN(rawUser, "_", 2)
	if len(parts) != 2 {
		newChannel.Reject(ssh.ConnectionFailed, "format must be user_ip")
		return
	}
	realUser := parts[0]
	targetIP := parts[1]
	log.Printf("[SESSION] user=%s target=%s", realUser, targetIP)

	credResp, err := p.AuditClient.GetBackendCredentials(context.Background(), &pb.CredentialRequest{TargetIp: targetIP})
	if err != nil {
		log.Printf("[ERROR] credential error: %v", err)
		newChannel.Reject(ssh.ConnectionFailed, "no credential")
		return
	}

	backendConfig := &ssh.ClientConfig{
		User:            realUser,
		Auth:            []ssh.AuthMethod{ssh.Password(credResp.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	backendClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", targetIP), backendConfig)
	if err != nil {
		log.Printf("[ERROR] backend connect failed: %v", err)
		newChannel.Reject(ssh.ConnectionFailed, "backend failed")
		return
	}
	defer backendClient.Close()

	backendSession, err := backendClient.NewSession()
	if err != nil {
		log.Printf("[ERROR] session create failed: %v", err)
		return
	}
	defer backendSession.Close()

	stdin, _ := backendSession.StdinPipe()
	stdout, _ := backendSession.StdoutPipe()
	stderr, _ := backendSession.StderrPipe()

	clientChan, clientReqs, err := newChannel.Accept()
	if err != nil {
		log.Printf("[ERROR] accept failed: %v", err)
		return
	}

	go func() {
		for req := range clientReqs {
			ok, _ := backendSession.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(ok, nil)
			}
		}
	}()

	go p.interceptAndForward(clientChan, stdin, rawUser)
	go io.Copy(clientChan, stdout)
	go io.Copy(clientChan.Stderr(), stderr)

	select {}
}

// interceptAndForward 命令审计核心
func (p *Proxy) interceptAndForward(client io.Reader, backend io.Writer, user string) {
	var bufLine bytes.Buffer
	buf := make([]byte, 1)

	for {
		n, err := client.Read(buf)
		if n > 0 {
			ch := buf[0]
			bufLine.WriteByte(ch)

			if ch == '\n' || ch == '\r' {
				cmd := bufLine.String()
				log.Printf("[CMD] %s", cmd)

				resp, err := p.AuditClient.CheckCommand(context.Background(), &pb.CommandRequest{Command: cmd, User: user})
				if err != nil {
					backend.Write(bufLine.Bytes())
					bufLine.Reset()
					continue
				}

				if !resp.Allowed {
					log.Printf("[BLOCK] %s reason=%s", cmd, resp.Reason)
					bufLine.Reset()
					continue
				}

				p.AuditClient.LogCommand(context.Background(), &pb.LogRequest{Command: cmd, User: user})
				backend.Write(bufLine.Bytes())
				bufLine.Reset()
			}
		}

		if err != nil {
			return
		}
	}
}
