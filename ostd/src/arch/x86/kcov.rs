// SPDX-License-Identifier: MPL-2.0

//! x86-64 System V AMD64 SanitizerCoverage callback trampolines.

use crate::kcov;

// SAFETY: LLVM SanitizerCoverage invokes this symbol as a standard System V
// AMD64 function. Its return address sits at `[rsp]` with `rsp % 16 == 8`;
// tail-jumping to `record_pc` preserves stack alignment and return address
// while passing the caller PC in `rdi`.
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_pc() {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "jmp {}",
        sym kcov::record_pc,
    );
}

// The System V AMD64 arguments arrive in `rdi` and `rsi`. Zero-extend subword
// operands before tail-jumping because the caller may leave upper bits
// unspecified.
macro_rules! trace_cmp_callback {
    ($name:ident, $arg_ty:ty, $kind:expr $(, $extend:literal)*) => {
        // SAFETY: Invoked by LLVM SanitizerCoverage as a standard System V
        // AMD64 function `($arg_ty, $arg_ty)`. Tail-jumping to `record_cmp`
        // preserves the caller's return address and stack alignment
        // (`rsp % 16 == 8`) while passing `(arg1, arg2, cmp_type, return_ip)`
        // in `(rdi, rsi, rdx, rcx)`.
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        extern "C" fn $name(_arg1: $arg_ty, _arg2: $arg_ty) {
            core::arch::naked_asm!(
                $($extend,)*
                "mov edx, {kind}",
                "mov rcx, [rsp]",
                "jmp {record}",
                kind = const $kind,
                record = sym kcov::record_cmp,
            );
        }
    };
}

trace_cmp_callback!(
    __sanitizer_cov_trace_cmp1,
    u8,
    kcov::KCOV_CMP_SIZE1,
    "movzx edi, dil",
    "movzx esi, sil"
);
trace_cmp_callback!(
    __sanitizer_cov_trace_cmp2,
    u16,
    kcov::KCOV_CMP_SIZE2,
    "movzx edi, di",
    "movzx esi, si"
);
trace_cmp_callback!(
    __sanitizer_cov_trace_cmp4,
    u32,
    kcov::KCOV_CMP_SIZE4,
    "mov edi, edi",
    "mov esi, esi"
);
trace_cmp_callback!(__sanitizer_cov_trace_cmp8, u64, kcov::KCOV_CMP_SIZE8);
trace_cmp_callback!(
    __sanitizer_cov_trace_const_cmp1,
    u8,
    kcov::KCOV_CMP_SIZE1 | kcov::KCOV_CMP_CONST,
    "movzx edi, dil",
    "movzx esi, sil"
);
trace_cmp_callback!(
    __sanitizer_cov_trace_const_cmp2,
    u16,
    kcov::KCOV_CMP_SIZE2 | kcov::KCOV_CMP_CONST,
    "movzx edi, di",
    "movzx esi, si"
);
trace_cmp_callback!(
    __sanitizer_cov_trace_const_cmp4,
    u32,
    kcov::KCOV_CMP_SIZE4 | kcov::KCOV_CMP_CONST,
    "mov edi, edi",
    "mov esi, esi"
);
trace_cmp_callback!(
    __sanitizer_cov_trace_const_cmp8,
    u64,
    kcov::KCOV_CMP_SIZE8 | kcov::KCOV_CMP_CONST
);

/// Records a SanitizerCoverage switch-statement comparison against all cases.
///
/// # Safety
///
/// If `_cases` is non-null, it must be properly aligned and point to a
/// readable `u64` table `[num_cases, val_bits, case_0, ..., case_{num_cases - 1}]`
/// valid for the duration of the call.
// SAFETY: Invoked by LLVM SanitizerCoverage as a standard System V AMD64
// function `(val: u64, cases: *const u64)`. Tail-jumping to `record_switch`
// preserves the caller's return address and stack alignment (`rsp % 16 == 8`)
// while passing the return IP in `rdx`.
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn __sanitizer_cov_trace_switch(_val: u64, _cases: *const u64) {
    core::arch::naked_asm!(
        "mov rdx, [rsp]",
        "jmp {}",
        sym kcov::record_switch,
    );
}
