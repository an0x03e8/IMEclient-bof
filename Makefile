# IMEclient-bof - root build.
#   all    cross-compile common/ + link the BOF COFFs into dist/
#   obj    common/ objects only
#   clean  remove build/ and dist/

ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
include $(ROOT)/build.mk

COMMON_SRCS     := $(wildcard $(ROOT)/common/*.c)
COMMON_OBJS_X64 := $(patsubst $(ROOT)/common/%.c,$(OBJ)/%.x64.o,$(COMMON_SRCS))

.PHONY: all obj clean

obj: $(COMMON_OBJS_X64)
	@echo "obj: $(words $(COMMON_OBJS_X64)) object(s) in $(OBJ)"

# Final COFFs land in dist/<name>.x64.o. Shared objects (http, ime_api,
# ime_util, print) are linked into every BOF; unused symbols in a given
# BOF are harmless.
DISTDIR := $(ROOT)/dist

# Library search paths, queried from the cross gcc itself (the same
# thing boflink's deprecated --mingw64/--ucrt64 shorthands did; explicit
# -L flags keep us ready for when those are removed).
MINGW_LIBS := $(shell $(CC_X64) -print-search-dirs | \
               sed -n 's/^libraries: =*//p' | tr ':' '\n' | \
               while read -r d; do [ -d "$$d" ] && printf '%s ' "$$d"; done)

LINKCMD  := $(BOFLINK) $(foreach d,$(MINGW_LIBS),-L$(d))
LINKLIBS := -lkernel32 -ladvapi32 -lwinhttp -lmsvcrt -luuid -lsecur32 -lgcc

OBJS_HTTP  := $(OBJ)/bof_http.x64.o
OBJS_UTIL  := $(OBJ)/bof_ime_util.x64.o
OBJS_PRINT := $(OBJ)/bof_print.x64.o
OBJS_API   := $(OBJ)/bof_ime_api.x64.o
OBJS_COMMON := $(OBJS_HTTP) $(OBJS_UTIL) $(OBJS_API) $(OBJS_PRINT) \
               $(COMMON_OBJS_X64)

BOF_TARGETS := $(DISTDIR)/ime_auth.x64.o \
               $(DISTDIR)/ime_list.x64.o \
               $(DISTDIR)/ime_install.x64.o \
               $(DISTDIR)/ime_checkin.x64.o \
               $(DISTDIR)/ime_token.x64.o

BOF_SRCS := print http ime_auth ime_api ime_util ime_list ime_install \
            ime_checkin ime_token wcfpipe wam

# mingw 13-win32 ships no libcombase.a; dlltool src/combase.def for wam.o.
COMBASE_A := $(OBJ)/libcombase.a

$(COMBASE_A): $(ROOT)/src/combase.def
	@mkdir -p $(OBJ)
	x86_64-w64-mingw32-dlltool -d $< -l $@

BOF_OBJS := $(addprefix $(OBJ)/bof_,$(addsuffix .x64.o,$(BOF_SRCS)))

$(BOF_OBJS): $(OBJ)/bof_%.x64.o: $(ROOT)/src/%.c $(wildcard $(ROOT)/src/*.h) $(wildcard $(ROOT)/common/*.h)
	@mkdir -p $(OBJ)
	$(CC_X64) $(CFLAGS_X64) -c -o $@ $<

all: $(BOF_TARGETS)
	@echo "[all] $(words $(BOF_TARGETS)) COFF(s) in dist/:"; ls $(DISTDIR) 2>/dev/null | sed "s/^/  /"

$(DISTDIR)/ime_auth.x64.o: $(OBJ)/bof_ime_auth.x64.o $(OBJS_COMMON)
$(DISTDIR)/ime_list.x64.o: $(OBJ)/bof_ime_list.x64.o $(OBJS_COMMON)
$(DISTDIR)/ime_install.x64.o: $(OBJ)/bof_ime_install.x64.o $(OBJS_COMMON)
$(DISTDIR)/ime_checkin.x64.o: $(OBJ)/bof_ime_checkin.x64.o $(OBJ)/bof_wcfpipe.x64.o $(OBJS_COMMON)
$(DISTDIR)/ime_token.x64.o: $(OBJ)/bof_ime_token.x64.o $(OBJ)/bof_wam.x64.o $(OBJS_COMMON) $(COMBASE_A)

$(DISTDIR)/%.x64.o:
	@mkdir -p $(DISTDIR)
	$(LINKCMD) $^ --entry=go $(LINKLIBS) -o $@

$(DISTDIR)/ime_token.x64.o: LINKLIBS += -L$(OBJ) -lcombase
$(DISTDIR)/ime_auth.x64.o: LINKLIBS += -lcrypt32

# --- common/ cross objects -------------------------------------------------
$(OBJ)/%.x64.o: $(ROOT)/common/%.c $(wildcard $(ROOT)/common/*.h)
	@mkdir -p $(OBJ)
	$(CC_X64) $(CFLAGS_X64) -c -o $@ $<

clean:
	rm -rf $(BUILD) $(DISTDIR)
