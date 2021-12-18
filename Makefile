
ifdef TBOX
    TBOX_OPT := "-DTBOX"
endif

all : test

aes : aes.o
	gcc aes.c -c -o aes.o $(TBOX_OPT) 
	gcc aes.o -o aes $(TBOX_OPT)

aes.o : aes.c
	gcc aes.c -c $(TBOX_OPT) 

main.o : main.c
	gcc main.c -c $(TBOX_OPT) 

test : main.o aes.o
	strip -Nmain aes.o
	gcc main.o aes.o -o test

clean : 
	rm *.o test aes

.PHONY : clean
