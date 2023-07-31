static unsigned long canonicalize_ip(unsigned long ip)
{
#ifdef CONFIG_RANDOMIZE_BASE
	ip -= kaslr_offset();
#endif
	return ip;
}

void notrace __sanitizer_cov_trace_pcwithsvranges(int sv_no, int sv_value, int rw_type)
{
        int head = 0x1111;
        struct task_struct *t;
        enum kcov_mode mode;

        t = current;
        /*
         * We are interested in code coverage as a function of a syscall inputs,
         * so we ignore code executed in interrupts.
         */
        if (!t || !in_task())
                return;
        mode = READ_ONCE(t->kcov_mode);
        if (mode == KCOV_MODE_TRACE) {
                unsigned long *area;
                unsigned long pos;
                unsigned long ip;

                /*
                 * There is some code that runs in interrupts but for which
                 * in_interrupt() returns false (e.g. preempt_schedule_irq()).
                 * READ_ONCE()/barrier() effectively provides load-acquire wrt
                 * interrupts, there are paired barrier()/WRITE_ONCE() in
                 * kcov_ioctl_locked().
                 */
                barrier();
                area = t->kcov_area;

                ip = ((unsigned long)(head) << 48) + ((unsigned long)(rw_type) << 47) + ((unsigned long)(sv_no) << 32) + (unsigned)(sv_value & 0xffffffff);
                if (likely(pos < t->kcov_size)) {
                    area[pos] = ip;
                    WRITE_ONCE(area[0], pos);
                }

                // send current pc
                pos = READ_ONCE(area[0]) + 1;
                ip = (canonicalize_ip(_RET_IP_) & 0x00000000ffffffff) | 0xdeadbeef00000000;
	            if (likely(pos < t->kcov_size)) {
	            	area[pos] = ip;
	            	WRITE_ONCE(area[0], pos);
	            }
        }
}
EXPORT_SYMBOL(__sanitizer_cov_trace_pcwithsvranges);


// trace_cmp
#define KCOV_WORDS_PER_CMP 4


#ifdef CONFIG_KCOV
static void write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
{
	struct task_struct *t;
	u64 *area;
	u64 count, start_index, end_pos, max_pos;

	t = current;
	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
		return;

	ip = canonicalize_ip(ip);

	/*
	 * We write all comparison arguments and types as u64.
	 * The buffer was allocated for t->kcov_size unsigned longs.
	 */
	area = (u64 *)t->kcov_area;
	max_pos = t->kcov_size * sizeof(unsigned long);

	count = READ_ONCE(area[0]);

	/* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
	start_index = 1 + count * KCOV_WORDS_PER_CMP;
	end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
	if (likely(end_pos <= max_pos)) {
		area[start_index] = type;
		area[start_index + 1] = arg1;
		area[start_index + 2] = arg2;
		area[start_index + 3] = ip;
		WRITE_ONCE(area[0], count + 1);
	}
}

void notrace __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
{
	write_comp_data(KCOV_CMP_SIZE(0), arg1, arg2, _RET_IP_);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_cmp1);

void notrace __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2)
{
	write_comp_data(KCOV_CMP_SIZE(1), arg1, arg2, _RET_IP_);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_cmp2);

void notrace __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2)
{
	write_comp_data(KCOV_CMP_SIZE(2), arg1, arg2, _RET_IP_);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_cmp4);

void notrace __sanitizer_cov_trace_cmp8(u64 arg1, u64 arg2)
{
	write_comp_data(KCOV_CMP_SIZE(3), arg1, arg2, _RET_IP_);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_cmp8);

void notrace __sanitizer_cov_trace_const_cmp1(u8 arg1, u8 arg2)
{
	write_comp_data(KCOV_CMP_SIZE(0) | KCOV_CMP_CONST, arg1, arg2,
			_RET_IP_);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp1);

void notrace __sanitizer_cov_trace_const_cmp2(u16 arg1, u16 arg2)
{
	write_comp_data(KCOV_CMP_SIZE(1) | KCOV_CMP_CONST, arg1, arg2,
			_RET_IP_);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp2);

void notrace __sanitizer_cov_trace_const_cmp4(u32 arg1, u32 arg2)
{
	write_comp_data(KCOV_CMP_SIZE(2) | KCOV_CMP_CONST, arg1, arg2,
			_RET_IP_);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp4);

void notrace __sanitizer_cov_trace_const_cmp8(u64 arg1, u64 arg2)
{
	write_comp_data(KCOV_CMP_SIZE(3) | KCOV_CMP_CONST, arg1, arg2,
			_RET_IP_);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp8);

void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)
{
	u64 i;
	u64 count = cases[0];
	u64 size = cases[1];
	u64 type = KCOV_CMP_CONST;

	switch (size) {
	case 8:
		type |= KCOV_CMP_SIZE(0);
		break;
	case 16:
		type |= KCOV_CMP_SIZE(1);
		break;
	case 32:
		type |= KCOV_CMP_SIZE(2);
		break;
	case 64:
		type |= KCOV_CMP_SIZE(3);
		break;
	default:
		return;
	}
	for (i = 0; i < count; i++)
		write_comp_data(type, cases[i + 2], val, _RET_IP_);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_switch);
#endif /* ifdef CONFIG_KCOV_ENABLE_COMPARISONS */



// include/uapi/linux/kcov.h
enum {
	/*
	 * Tracing coverage collection mode.
	 * Covered PCs are collected in a per-task buffer.
	 * In new KCOV version the mode is chosen by calling
	 * ioctl(fd, KCOV_ENABLE, mode). In older versions the mode argument
	 * was supposed to be 0 in such a call. So, for reasons of backward
	 * compatibility, we have chosen the value KCOV_TRACE_PC to be 0.
	 */
	KCOV_TRACE_PC = 0,
	/* Collecting comparison operands mode. */
	KCOV_TRACE_CMP = 1,
};

/*
 * The format for the types of collected comparisons.
 *
 * Bit 0 shows whether one of the arguments is a compile-time constant.
 * Bits 1 & 2 contain log2 of the argument size, up to 8 bytes.
 */
#define KCOV_CMP_CONST          (1 << 0)
#define KCOV_CMP_SIZE(n)        ((n) << 1)
#define KCOV_CMP_MASK           KCOV_CMP_SIZE(3)



// include/linux/kcov.h
enum kcov_mode {
	/* Coverage collection is not enabled yet. */
	KCOV_MODE_DISABLED = 0,
	/* KCOV was initialized, but tracing mode hasn't been chosen yet. */
	KCOV_MODE_INIT = 1,
	/*
	 * Tracing coverage collection mode.
	 * Covered PCs are collected in a per-task buffer.
	 */
	KCOV_MODE_TRACE_PC = 2,
	/* Collecting comparison operands mode. */
	KCOV_MODE_TRACE_CMP = 3,
};
