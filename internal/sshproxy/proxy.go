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

// ============================
// 全局状态：当前SSH连接数
// ============================
var activeConnections int32

// ============================
// Proxy：SSH堡垒机核心结构
// ============================
// 负责：
// 1. SSH接入
// 2. 命令拦截
// 3. 审计调用
// 4. 转发到后端服务器
type Proxy struct {
	Config      *config.BastionConfig // 配置（监听地址/密码/hostkey等）
	AuditClient pb.AuditClient        // gRPC审计客户端
}

// ============================
// Start：启动SSH堡垒机服务
// ============================
func (p *Proxy) Start() error {

	// 调试：打印堡垒机密码
	log.Printf("[DEBUG] BastionPass from config: '%s'", p.Config.BastionPass)

	// ============================
	// 1. SSH服务配置
	// ============================
	sshConfig := &ssh.ServerConfig{

		// SSH密码认证回调函数
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {

			log.Printf("[AUTH] Received password: '%s'", pass)
			log.Printf("[AUTH] Expected password: '%s'", p.Config.BastionPass)

			// 验证堡垒机登录密码
			if string(pass) == p.Config.BastionPass {
				log.Printf("[AUTH] Password accepted for user: %s", c.User())
				return nil, nil
			}

			log.Printf("[AUTH] Password rejected for user: %s", c.User())
			return nil, fmt.Errorf("password rejected")
		},
	}

	// ============================
	// 2. 加载SSH HostKey（服务器身份）
	// ============================
	keyBytes, err := os.ReadFile(p.Config.HostKey)
	if err != nil {
		return err
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return err
	}

	sshConfig.AddHostKey(signer)

	// ============================
	// 3. 启动TCP监听
	// ============================
	listener, err := net.Listen("tcp", p.Config.ListenAddr)
	if err != nil {
		return err
	}

	log.Printf("Bastion listening on %s", p.Config.ListenAddr)

	// ============================
	// 4. 状态监控协程（每10秒打印连接数）
	// ============================
	go func() {
		for {
			time.Sleep(10 * time.Second)
			log.Printf("[State] Active SSH Connections: %d",
				atomic.LoadInt32(&activeConnections))
		}
	}()

	// ============================
	// 5. 接收SSH连接
	// ============================
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		// 每个连接单独协程处理
		go p.handleConnection(conn, sshConfig)
	}
}

// ============================
// handleConnection：处理SSH握手
// ============================
func (p *Proxy) handleConnection(nConn net.Conn, config *ssh.ServerConfig) {

	log.Printf("[DEBUG] New incoming connection from %s", nConn.RemoteAddr())

	// SSH握手
	serverConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("[ERROR] SSH handshake failed: %v", err)
		return
	}
	defer serverConn.Close()

	log.Printf("[INFO] SSH connection established user: %s", serverConn.User())

	// 忽略全局请求（keepalive等）
	go ssh.DiscardRequests(reqs)

	// ============================
	// 处理所有channel请求
	// ============================
	for newChannel := range chans {

		log.Printf("[DEBUG] New channel type: %s", newChannel.ChannelType())

		// 只允许session类型
		if newChannel.ChannelType() != "session" {
			log.Printf("[ERROR] Reject channel type %s", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		// 处理会话
		go p.handleSession(newChannel, serverConn)
	}

	log.Printf("[INFO] Connection closed for user: %s", serverConn.User())
}

// ============================
// handleSession：核心堡垒机逻辑
// ============================
// 功能：
// 1. 解析 user_targetIP
// 2. 连接后端SSH
// 3. 拦截命令
// 4. 转发流量
func (p *Proxy) handleSession(newChannel ssh.NewChannel, clientConn *ssh.ServerConn) {

	// 当前连接数 +1
	atomic.AddInt32(&activeConnections, 1)
	defer atomic.AddInt32(&activeConnections, -1)

	rawUser := clientConn.User()

	log.Printf("[SESSION] Start user: %s", rawUser)

	// ============================
	// 1. 解析用户格式 user_ip
	// ============================
	parts := strings.SplitN(rawUser, "_", 2)
	if len(parts) != 2 {
		newChannel.Reject(ssh.ConnectionFailed, "Invalid format: use user_ip")
		return
	}

	realUser := parts[0]
	targetIP := parts[1]

	log.Printf("[SESSION] realUser=%s targetIP=%s", realUser, targetIP)

	// ============================
	// 2. 获取后端SSH密码（RPC）
	// ============================
	credResp, err := p.AuditClient.GetBackendCredentials(
		context.Background(),
		&pb.CredentialRequest{
			TargetIp: rawUser, // ⚠️（这里是设计点，可优化）
		},
	)

	if err != nil {
		log.Printf("[ERROR] RPC GetBackendCredentials failed: %v", err)
		newChannel.Reject(ssh.ConnectionFailed, "credential error")
		return
	}

	log.Printf("[SESSION] backend password acquired")

	// ============================
	// 3. 连接后端SSH服务器
	// ============================
	backendConfig := &ssh.ClientConfig{
		User: realUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(credResp.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	backendClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", targetIP), backendConfig)
	if err != nil {
		log.Printf("[ERROR] backend connect failed: %v", err)
		newChannel.Reject(ssh.ConnectionFailed, "backend connection failed")
		return
	}
	defer backendClient.Close()

	log.Printf("[SESSION] connected to backend")

	// ============================
	// 4. 创建后端session
	// ============================
	backendSession, err := backendClient.NewSession()
	if err != nil {
		log.Printf("[ERROR] create session failed: %v", err)
		return
	}
	defer backendSession.Close()

	// 获取管道
	backendStdin, _ := backendSession.StdinPipe()
	backendStdout, _ := backendSession.StdoutPipe()
	backendStderr, _ := backendSession.StderrPipe()

	// ============================
	// 5. 接受客户端channel
	// ============================
	clientChan, clientReqs, err := newChannel.Accept()
	if err != nil {
		log.Printf("[ERROR] accept channel failed: %v", err)
		return
	}

	// ============================
	// 6. 转发SSH请求（pty/env等）
	// ============================
	go func() {
		for req := range clientReqs {

			ok, err := backendSession.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Printf("[ERROR] request forward failed: %v", err)
			}

			if req.WantReply {
				req.Reply(ok, nil)
			}
		}
	}()

	// ============================
	// 7. 数据转发 + 命令拦截
	// ============================
	go p.interceptAndForward(clientChan, backendStdin, rawUser)
	go io.Copy(clientChan, backendStdout)
	go io.Copy(clientChan.Stderr(), backendStderr)

	// ============================
	// 8. 等待会话结束
	// ============================
	exitChan := make(chan struct{}, 1)

	go func() {
		p.interceptAndForward(clientChan, backendStdin, rawUser)
		exitChan <- struct{}{}
	}()

	go func() {
		io.Copy(clientChan, backendStdout)
		exitChan <- struct{}{}
	}()

	go func() {
		io.Copy(clientChan.Stderr(), backendStderr)
	}()

	<-exitChan

	clientChan.Close()

	log.Printf("[SESSION] ended user=%s", rawUser)
}

// ============================
// interceptAndForward：命令审计核心
// ============================
// 功能：逐字符读取命令 -> 拼接 -> 调用审计服务
func (p *Proxy) interceptAndForward(client io.Reader, backend io.Writer, user string) {

	var lineBuf bytes.Buffer
	buf := make([]byte, 1)

	for {
		n, err := client.Read(buf)
		if n > 0 {

			char := buf[0]
			lineBuf.WriteByte(char)

			// 遇到换行：认为一条命令结束
			if char == '\r' || char == '\n' {

				cmdStr := lineBuf.String()
				log.Printf("[INTERCEPT] cmd=%q", cmdStr)

				// ============================
				// 1. 调用审计服务检查命令
				// ============================
				resp, err := p.AuditClient.CheckCommand(
					context.Background(),
					&pb.CommandRequest{
						Command: cmdStr,
						User:    user,
					},
				)

				// RPC失败：默认放行
				if err != nil {
					log.Printf("[ERROR] audit RPC failed: %v", err)
					backend.Write(lineBuf.Bytes())
					lineBuf.Reset()
					continue
				}

				// ============================
				// 2. 命令被拦截
				// ============================
				if !resp.Allowed {
					log.Printf("[BLOCKED] %s reason=%s", cmdStr, resp.Reason)
					lineBuf.Reset()
					continue
				}

				// ============================
				// 3. 命令通过
				// ============================
				log.Printf("[ALLOWED] %s", cmdStr)

				// 记录审计日志
				p.AuditClient.LogCommand(context.Background(), &pb.LogRequest{
					Command: cmdStr,
					User:    user,
				})

				// 转发到后端
				backend.Write(lineBuf.Bytes())
				lineBuf.Reset()
			}
		}

		if err != nil {
			log.Printf("[INTERCEPT] read error: %v", err)
			break
		}
	}
}
