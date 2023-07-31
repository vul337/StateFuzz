// AUTOGENERATED FILE
//go:build !codeanalysis && (!syz_target || (syz_target && syz_os_trusty && syz_arch_arm))
// +build !codeanalysis
// +build !syz_target syz_target,syz_os_trusty,syz_arch_arm

package gen

import . "github.com/google/syzkaller/prog"
import . "github.com/google/syzkaller/sys/trusty"

func init() {
	RegisterTarget(&Target{OS: "trusty", Arch: "arm", Revision: revision_arm, PtrSize: 4, PageSize: 4096, NumPages: 4096, DataOffset: 536870912, Syscalls: syscalls_arm, Resources: resources_arm, Consts: consts_arm}, types_arm, InitTarget)
}

var resources_arm = []*ResourceDesc{
	{Name: "ANYRES16", Kind: []string{"ANYRES16"}, Values: []uint64{18446744073709551615, 0}},
	{Name: "ANYRES32", Kind: []string{"ANYRES32"}, Values: []uint64{18446744073709551615, 0}},
	{Name: "ANYRES64", Kind: []string{"ANYRES64"}, Values: []uint64{18446744073709551615, 0}},
}

var syscalls_arm = []*Syscall{
	{NR: 18, Name: "accept", CallName: "accept", Args: []Field{
		{"handle_id", Ref(3)},
		{"peer_uuid", Ref(17)},
	}},
	{NR: 2, Name: "brk", CallName: "brk", Args: []Field{
		{"brk", Ref(3)},
	}},
	{NR: 19, Name: "close", CallName: "close", Args: []Field{
		{"handle_id", Ref(3)},
	}},
	{NR: 17, Name: "connect", CallName: "connect", Args: []Field{
		{"path", Ref(11)},
		{"flags", Ref(3)},
	}},
	{NR: 3, Name: "exit_etc", CallName: "exit_etc", Args: []Field{
		{"status", Ref(3)},
		{"flags", Ref(3)},
	}},
	{NR: 11, Name: "finish_dma", CallName: "finish_dma", Args: []Field{
		{"uaddr", Ref(22)},
		{"size", Ref(7)},
		{"flags", Ref(3)},
	}},
	{NR: 32, Name: "get_msg", CallName: "get_msg", Args: []Field{
		{"handle", Ref(3)},
		{"msg_info", Ref(15)},
	}},
	{NR: 7, Name: "gettime", CallName: "gettime", Args: []Field{
		{"clock_id", Ref(3)},
		{"flags", Ref(3)},
		{"time", Ref(18)},
	}},
	{NR: 21, Name: "handle_set_create", CallName: "handle_set_create"},
	{NR: 22, Name: "handle_set_ctrl", CallName: "handle_set_ctrl", Args: []Field{
		{"handle", Ref(3)},
		{"cmd", Ref(3)},
		{"evt", Ref(8)},
	}},
	{NR: 5, Name: "ioctl", CallName: "ioctl", Args: []Field{
		{"fd", Ref(3)},
		{"req", Ref(3)},
		{"buf", Ref(14)},
	}},
	{NR: 8, Name: "mmap", CallName: "mmap", Args: []Field{
		{"uaddr", Ref(29)},
		{"size", Ref(7)},
		{"flags", Ref(3)},
		{"handle", Ref(3)},
	}},
	{NR: 9, Name: "munmap", CallName: "munmap", Args: []Field{
		{"uaddr", Ref(29)},
		{"size", Ref(7)},
	}},
	{NR: 6, Name: "nanosleep", CallName: "nanosleep", Args: []Field{
		{"clock_id", Ref(3)},
		{"flags", Ref(3)},
		{"sleep_time", Ref(4)},
	}},
	{NR: 16, Name: "port_create", CallName: "port_create", Args: []Field{
		{"path", Ref(11)},
		{"num_recv_bufs", Ref(3)},
		{"recv_buf_size", Ref(3)},
		{"flags", Ref(3)},
	}},
	{NR: 10, Name: "prepare_dma", CallName: "prepare_dma", Args: []Field{
		{"uaddr", Ref(22)},
		{"size", Ref(7)},
		{"flags", Ref(3)},
		{"pmem", Ref(9)},
	}},
	{NR: 34, Name: "put_msg", CallName: "put_msg", Args: []Field{
		{"handle", Ref(3)},
		{"msg_id", Ref(3)},
	}},
	{NR: 4, Name: "read", CallName: "read", Args: []Field{
		{"fd", Ref(3)},
		{"msg", Ref(22)},
		{"size", Ref(6)},
	}},
	{NR: 33, Name: "read_msg", CallName: "read_msg", Args: []Field{
		{"handle", Ref(3)},
		{"msg_id", Ref(3)},
		{"offset", Ref(3)},
		{"msg", Ref(20)},
	}},
	{NR: 35, Name: "send_msg", CallName: "send_msg", Args: []Field{
		{"handle", Ref(3)},
		{"msg", Ref(10)},
	}},
	{NR: 20, Name: "set_cookie", CallName: "set_cookie", Args: []Field{
		{"handle", Ref(3)},
		{"cookie", Ref(5)},
	}},
	{Name: "syz_builtin0", CallName: "syz_builtin0", Args: []Field{
		{"a", Ref(13)},
	}, Attrs: SyscallAttrs{Disabled: true}},
	{Name: "syz_builtin1", CallName: "syz_builtin1", Args: []Field{
		{"a", Ref(21)},
	}, Attrs: SyscallAttrs{Disabled: true}},
	{NR: 24, Name: "wait", CallName: "wait", Args: []Field{
		{"handle_id", Ref(3)},
		{"event", Ref(8)},
		{"timeout_msecs", Ref(3)},
	}},
	{NR: 25, Name: "wait_any", CallName: "wait_any", Args: []Field{
		{"event", Ref(19)},
		{"timeout_msecs", Ref(3)},
	}},
	{NR: 1, Name: "write", CallName: "write", Args: []Field{
		{"fd", Ref(3)},
		{"msg", Ref(14)},
		{"size", Ref(6)},
	}},
}

var types_arm = []Type{
	&ArrayType{TypeCommon: TypeCommon{TypeName: "array", IsVarlen: true}, Elem: Ref(31)},
	&BufferType{TypeCommon: TypeCommon{TypeName: "array", IsVarlen: true}},
	&BufferType{TypeCommon: TypeCommon{TypeName: "string", IsVarlen: true}, Kind: 2},
	&IntType{IntTypeCommon: IntTypeCommon{TypeCommon: TypeCommon{TypeName: "int32", TypeSize: 4}}},
	&IntType{IntTypeCommon: IntTypeCommon{TypeCommon: TypeCommon{TypeName: "int64", TypeSize: 8}}},
	&IntType{IntTypeCommon: IntTypeCommon{TypeCommon: TypeCommon{TypeName: "intptr", TypeSize: 4}}},
	&LenType{IntTypeCommon: IntTypeCommon{TypeCommon: TypeCommon{TypeName: "len", TypeSize: 4}}, Path: []string{"msg"}},
	&LenType{IntTypeCommon: IntTypeCommon{TypeCommon: TypeCommon{TypeName: "len", TypeSize: 4}}, Path: []string{"uaddr"}},
	&PtrType{TypeCommon: TypeCommon{TypeName: "ptr", TypeSize: 4}, Elem: Ref(35)},
	&PtrType{TypeCommon: TypeCommon{TypeName: "ptr", TypeSize: 4}, Elem: Ref(32)},
	&PtrType{TypeCommon: TypeCommon{TypeName: "ptr", TypeSize: 4}, Elem: Ref(33)},
	&PtrType{TypeCommon: TypeCommon{TypeName: "ptr", TypeSize: 4}, Elem: Ref(2)},
	&PtrType{TypeCommon: TypeCommon{TypeName: "ptr", TypeSize: 4}, Elem: Ref(0)},
	&PtrType{TypeCommon: TypeCommon{TypeName: "ptr", TypeSize: 4}, Elem: Ref(30)},
	&PtrType{TypeCommon: TypeCommon{TypeName: "ptr", TypeSize: 4}, Elem: Ref(1)},
	&PtrType{TypeCommon: TypeCommon{TypeName: "ptr", TypeSize: 4}, Elem: Ref(34)},
	&PtrType{TypeCommon: TypeCommon{TypeName: "ptr64", TypeSize: 8}, Elem: Ref(0)},
	&PtrType{TypeCommon{TypeName: "ptr", TypeSize: 4}, Ref(36), 1},
	&PtrType{TypeCommon{TypeName: "ptr", TypeSize: 4}, Ref(4), 1},
	&PtrType{TypeCommon{TypeName: "ptr", TypeSize: 4}, Ref(35), 1},
	&PtrType{TypeCommon{TypeName: "ptr", TypeSize: 4}, Ref(33), 1},
	&PtrType{TypeCommon{TypeName: "ptr", TypeSize: 4}, Ref(31), 1},
	&PtrType{TypeCommon{TypeName: "ptr", TypeSize: 4}, Ref(1), 1},
	&ResourceType{TypeCommon: TypeCommon{TypeName: "ANYRES16", TypeSize: 2}},
	&ResourceType{TypeCommon: TypeCommon{TypeName: "ANYRES32", TypeSize: 4}},
	&ResourceType{TypeCommon: TypeCommon{TypeName: "ANYRES64", TypeSize: 18}, ArgFormat: 3},
	&ResourceType{TypeCommon: TypeCommon{TypeName: "ANYRES64", TypeSize: 20}, ArgFormat: 2},
	&ResourceType{TypeCommon: TypeCommon{TypeName: "ANYRES64", TypeSize: 23}, ArgFormat: 4},
	&ResourceType{TypeCommon: TypeCommon{TypeName: "ANYRES64", TypeSize: 8}},
	&VmaType{TypeCommon: TypeCommon{TypeName: "vma", TypeSize: 4}},
	&UnionType{TypeCommon{TypeName: "ANYPTRS", TypeSize: 8}, []Field{
		{"ANYPTR", Ref(12)},
		{"ANYPTR64", Ref(16)},
	}},
	&UnionType{TypeCommon{TypeName: "ANYUNION", IsVarlen: true}, []Field{
		{"ANYBLOB", Ref(1)},
		{"ANYRES16", Ref(23)},
		{"ANYRES32", Ref(24)},
		{"ANYRES64", Ref(28)},
		{"ANYRESDEC", Ref(26)},
		{"ANYRESHEX", Ref(25)},
		{"ANYRESOCT", Ref(27)},
	}},
	&StructType{TypeCommon: TypeCommon{TypeName: "dma_pmem", TypeSize: 4}, Fields: []Field{
		{"todo", Ref(3)},
	}},
	&StructType{TypeCommon: TypeCommon{TypeName: "ipc_msg", TypeSize: 4}, Fields: []Field{
		{"todo", Ref(3)},
	}},
	&StructType{TypeCommon: TypeCommon{TypeName: "ipc_msg_info", TypeSize: 4}, Fields: []Field{
		{"todo", Ref(3)},
	}},
	&StructType{TypeCommon: TypeCommon{TypeName: "uevent", TypeSize: 4}, Fields: []Field{
		{"todo", Ref(3)},
	}},
	&StructType{TypeCommon: TypeCommon{TypeName: "uuid", TypeSize: 4}, Fields: []Field{
		{"todo", Ref(3)},
	}},
}

var consts_arm = []ConstValue{
	{"__NR_accept", 18},
	{"__NR_brk", 2},
	{"__NR_close", 19},
	{"__NR_connect", 17},
	{"__NR_exit_etc", 3},
	{"__NR_finish_dma", 11},
	{"__NR_get_msg", 32},
	{"__NR_gettime", 7},
	{"__NR_handle_set_create", 21},
	{"__NR_handle_set_ctrl", 22},
	{"__NR_ioctl", 5},
	{"__NR_mmap", 8},
	{"__NR_munmap", 9},
	{"__NR_nanosleep", 6},
	{"__NR_port_create", 16},
	{"__NR_prepare_dma", 10},
	{"__NR_put_msg", 34},
	{"__NR_read", 4},
	{"__NR_read_msg", 33},
	{"__NR_send_msg", 35},
	{"__NR_set_cookie", 20},
	{"__NR_wait", 24},
	{"__NR_wait_any", 25},
	{"__NR_write", 1},
}

const revision_arm = "1363e8972f80b2905f34f95d1481d43a4b2ffbf6"