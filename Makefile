program: injector.c, bcookesHalosGate.asm
	nasm -f elf64 HalosGate.asm -o HalosGate
	gcc -o injector injector.c HalosGate.o
	
clean:
	rm -rf injector.exe 