$(call add-hdrs,fd_bank_abi.h)
$(call add-objs,fd_bank_abi,fd_disco)
$(call make-fuzz-test,fuzz_bank_abi,fuzz_bank_abi,fd_disco fd_util fd_ballet)
