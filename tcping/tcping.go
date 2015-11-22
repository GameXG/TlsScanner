package main
import (
	"encoding/json"
	"log"
	"fmt"
	"os"
	"time"
	"net"
	"github.com/golang/glog"
	"crypto/tls"
	"strings"
)

const (
	taskCount = 100
	timeout = 5 * time.Second
)


type Domains map[string][]string
type Ips map[string][]string

type task struct {
	Domain []string
	Ip     string
	Ping   time.Duration
}



func main() {
	f, err := os.Open(`D:\golang\src\github.com\gamexg\TlsScanner\google-ip\ip.txt`)
	if err != nil {
		panic(err)
	}
	dec := json.NewDecoder(f)

	var domains = Domains{}
	if err := dec.Decode(&domains); err != nil {
		log.Fatal(err)
	}

	// 以IP为KEY
	var ips = Ips{}
	for d, _ips := range domains {
		for _, ip := range _ips {
			ips[ip] = append(ips[ip], d)
		}
	}

	taskResChan := make(chan *task, 10)

	// 填充任务队列
	taskChan := make(chan *task, 100)
	go func() {
		for ip, domains := range ips {
			taskChan <- &task{domains, ip, 0}
		}
		close(taskChan)
	}()

	// 启动任务
	endChan := make(chan int, 10)
	for i := 0; i < taskCount; i++ {
		go func() {
			defer func() { endChan <- 1}()
			for task := range taskChan {
				if len(task.Domain) == 0 {
					continue
				}
				odomain := task.Domain[0]
				odomain = strings.Replace(odomain, `*`, `www`, -1)
				t := time.Now()
				c, err := tls.DialWithDialer(&net.Dialer{Timeout:timeout}, "tcp", fmt.Sprint(task.Ip, ":443"), &tls.Config{ServerName:odomain})
				if err == nil {
					task.Ping = time.Now().Sub(t)
					ndomains := make([]string, 0, len(task.Domain))
					for _, v := range task.Domain {
						if v != "" && c.VerifyHostname(v) == nil {
							ndomains = append(ndomains, v)
						}else {
							fmt.Println(task.Ip, " 无法验证域名：", v)
						}
					}

					c.Close()
					task.Domain = ndomains
					fmt.Printf("tcping %v(%v)\t%v\r\n", task.Domain, task.Ip, task.Ping)
					taskResChan <- task
				}else {
					fmt.Printf("tcping %v(%v)\t%v\r\n", task.Domain, task.Ip, err)
				}
			}
		}()
	}

	// 等待任务结束
	go func() {
		for i := 0; i < taskCount; i++ {
			<-endChan
		}
		close(taskResChan)
	}()

	// 回写文件
	resFile, err := os.OpenFile(`D:\golang\src\github.com\gamexg\TlsScanner\google-ip\ip-tcping-2.txt`, os.O_CREATE | os.O_TRUNC, 0666)
	if err != nil {
		panic(err)
	}
	defer resFile.Close()
	enc := json.NewEncoder(resFile)

	// 保存任务结果
	for taskRes := range taskResChan {
		if err := enc.Encode(taskRes); err != nil {
			glog.Warning(err)
		}
	}

}
