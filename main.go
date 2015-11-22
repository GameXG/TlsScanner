package main
import (
	"log"
	"os"
	"time"
	"fmt"
	"io"
	"net"
	"encoding/binary"
	"crypto/tls"
	"encoding/json"
	"path"
	"strconv"
)


/*

计划扫描 443 端口并保留证书信息

直接将tls状态信息序列化并保存

同时从标准输出及日志文件输出扫描记录。



*/

const timeout = 5 * time.Second

var logger *log.Logger

func initLog() {
	t := time.Now().Local().Format("2006-01-02-15-04-05")
	f, err := os.OpenFile("tls-" + t + ".log", os.O_APPEND | os.O_CREATE, os.ModePerm)
	if err != nil {
		panic(fmt.Sprint("日志错误:", err))
	}
	mw := io.MultiWriter(os.Stdout, f)

	logger = log.New(mw, "[TlsScanner]", log.Ltime)
}

func scanner(addr net.TCPAddr) {

	fname := fmt.Sprint("ip/", addr.IP[0], ".", addr.IP[1], "/", addr.IP.String(), "-", addr.Port, ".txt")

	dname := path.Dir(fname)
	os.MkdirAll(dname, os.ModePerm)

	if _, err := os.Stat(fname); err == nil {
		logger.Printf("已存在 %v ，跳过。", fname)
		return
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout:timeout}, "tcp", addr.String(), &tls.Config{InsecureSkipVerify :true})
	if err != nil {
	//	logger.Printf("连接 %v 失败：%v", addr, err)
		return
	}
	defer conn.Close()
	status := conn.ConnectionState()

	b, err := json.Marshal(status)
	if err != nil {
		logger.Printf("序列化失败：%v", err)
		return
	}

	f, err := os.Create(fname)
	if err != nil {
		logger.Printf("创建 %v 失败，跳过。详细错误:%v", fname, err)
		return
	}
	defer f.Close()

	if _, err := f.Write(b); err != nil {
		logger.Printf("写文件 %v 失败：%v", fname, err)
		return
	}
	logger.Printf("%v %v 成功。",conn.RemoteAddr(),status.PeerCertificates[0].Subject.CommonName)
}

func ipToUint32(ip string) (uint32, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return 0, fmt.Errorf("IP地址格式错误。", )
	}
	addr = addr.To4()

	return binary.BigEndian.Uint32([]byte(addr)), nil
}

func uint32ToIP(ip uint32) net.IP {
	addr := make([]byte, 4)
	binary.BigEndian.PutUint32(addr, ip)
	return net.IP(addr)
}

func scannerLoop(taskChan chan uint32, finishChan chan int) {
	for ip := range taskChan {
		addr := net.TCPAddr{uint32ToIP(ip), 443, ""}
		scanner(addr)
	}
	finishChan <- 1
}

func main() {
	if len(os.Args) != 4 {
		fmt.Print("https 证书扫描器\r\n请提供线程数、开始IP和结束IP。\r\n例如： 100 100.0.0.0 100.255.255.255")
		return
	}

	scannerThread, err := strconv.Atoi(os.Args[1])

	if err != nil || scannerThread <= 0 || scannerThread >= 10000 {
		fmt.Print("%v 不是合法的线程数。", os.Args[1])
		return
	}
	scannerThreadUint32 := uint32(scannerThread)

	startIP := os.Args[2]
	endIP := os.Args[3]

	initLog()
	taskChan := make(chan uint32, scannerThread * 2)
	finishChan := make(chan int)

	start, err := ipToUint32(startIP)
	if err != nil {
		panic("startIP错误")
	}
	end, err := ipToUint32(endIP)
	if err != nil {
		panic("endIP错误")
	}
	len := end - start

	for i := 0; i < scannerThread; i++ {
		go scannerLoop(taskChan, finishChan)
	}

	for i := uint32(0); i <= len; i++ {
		taskChan <- start + i
		if i <= scannerThreadUint32 {
			// 匀速建立连接
			time.Sleep(timeout / time.Duration(scannerThread))
		}
	}
	close(taskChan)

	for i := 0; i < scannerThread; i++ {
		<-finishChan
	}
}