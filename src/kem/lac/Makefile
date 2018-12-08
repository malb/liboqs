ifeq (x64,$(ARCH))
ENABLE_KEMS+=$(findstring lac_512_cca_kem, $(KEMS_TO_ENABLE))
MAKE_FLAGS_KEM_BIGQUAKE=
else ifeq (x86,$(ARCH))
ENABLE_KEMS+=$(findstring lac_512_cca_kem, $(KEMS_TO_ENABLE))
MAKE_FLAGS_KEM_BIGQUAKE=
endif

HEADERS_KEM_LAC=src/kem/lac/kem_lac.h
HEADERS_KEM+=$(HEADERS_KEM_LAC)

OBJECT_DIRS+=.objs/kem/lac
OBJECTS_KEM_LAC=.objs/kem/lac/kem_lac.o
OBJECTS_KEM+=$(OBJECTS_KEM_LAC)

.objs/kem/lac/kem_lac.o: headers src/kem/lac/kem_lac.c
	$(CC) -fPIC -c src/kem/lac/kem_lac.c -o .objs/kem/lac/kem_lac.o $(CFLAGS)

ifneq (,$(findstring lac_512_cca_kem, $(ENABLE_KEMS)))
UPSTREAMS+=kem_lac_512_cca_kem_upstream
endif

SRCS_KEM_LAC_512_CCA_KEM=src/kem/lac/upstream/Optimized_Implementation/ake.c \
	src/kem/lac/upstream/Optimized_Implementation/bch.c \
	src/kem/lac/upstream/Optimized_Implementation/bin-lwe.c \
	src/kem/lac/upstream/Optimized_Implementation/ecc.c \
	src/kem/lac/upstream/Optimized_Implementation/encrypt.c \
	src/kem/lac/upstream/Optimized_Implementation/ke.c \
	src/kem/lac/upstream/Optimized_Implementation/rand.c \
	src/kem/lac/upstream/Optimized_Implementation/kem.c 
OBJS_KEM_LAC_512_CCA_KEM=$(SRCS_KEM_LAC_512_CCA_KEM:.c=.o)
TO_CLEAN+=$(OBJS_KEM_LAC_512_CCA_KEM)

src/kem/lac/upstream/Optimized_Implementation/%.o: src/kem/lac/upstream/Optimized_Implementation/%.c
	$(CC) -fPIC -c -O3 -DNDEBUG -o $@ $<

kem_lac_512_cca_kem_upstream: $(OBJS_KEM_LAC_512_CCA_KEM)
	bash scripts/collect_objects.sh kem_lac_512_cca_kem $(OBJS_KEM_LAC_512_CCA_KEM)
	bash scripts/symbols_global_rename.sh kem_lac_512_cca_kem src/kem/lac/symbols_global_rename_512_cca_kem.txt
	bash scripts/symbols_local.sh kem_lac_512_cca_kem src/kem/lac/symbols_local.txt
