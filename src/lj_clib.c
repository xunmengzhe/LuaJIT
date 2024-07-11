/*
** FFI C library loader.
** Copyright (C) 2005-2023 Mike Pall. See Copyright Notice in luajit.h
*/

#include "lj_obj.h"

#if LJ_HASFFI

#include "lj_gc.h"
#include "lj_err.h"
#include "lj_tab.h"
#include "lj_str.h"
#include "lj_udata.h"
#include "lj_ctype.h"
#include "lj_cconv.h"
#include "lj_cdata.h"
#include "lj_clib.h"
#include "lj_strfmt.h"
#include "lj_debug.h"

/* -- OS-specific functions ----------------------------------------------- */

#if LJ_TARGET_DLOPEN

#include <dlfcn.h>
#include <stdio.h>

#if defined(RTLD_DEFAULT) && !defined(NO_RTLD_DEFAULT)
#define CLIB_DEFHANDLE	RTLD_DEFAULT
#elif LJ_TARGET_OSX || LJ_TARGET_BSD
#define CLIB_DEFHANDLE	((void *)(intptr_t)-2)
#else
#define CLIB_DEFHANDLE	NULL
#endif

LJ_NORET LJ_NOINLINE static void clib_error_(lua_State *L)
{
  lj_err_callermsg(L, dlerror());
}

#define clib_error(L, fmt, name)	clib_error_(L)

#if LJ_TARGET_CYGWIN
#define CLIB_SOPREFIX	"cyg"
#else
#define CLIB_SOPREFIX	"lib"
#endif

#if LJ_TARGET_OSX
#define CLIB_SOEXT	"%s.dylib"
#elif LJ_TARGET_CYGWIN
#define CLIB_SOEXT	"%s.dll"
#else
#define CLIB_SOEXT	"%s.so"
#endif

static const char *clib_extname(lua_State *L, const char *name)
{
  if (!strchr(name, '/')
#if LJ_TARGET_CYGWIN
      && !strchr(name, '\\')
#endif
     ) {
    if (!strchr(name, '.')) {
      name = lj_strfmt_pushf(L, CLIB_SOEXT, name);
      L->top--;
#if LJ_TARGET_CYGWIN
    } else {
      return name;
#endif
    }
    if (!(name[0] == CLIB_SOPREFIX[0] && name[1] == CLIB_SOPREFIX[1] &&
	  name[2] == CLIB_SOPREFIX[2])) {
      name = lj_strfmt_pushf(L, CLIB_SOPREFIX "%s", name);
      L->top--;
    }
  }
  return name;
}

/* Check for a recognized ld script line. */
static const char *clib_check_lds(lua_State *L, const char *buf)
{
  char *p, *e;
  if ((!strncmp(buf, "GROUP", 5) || !strncmp(buf, "INPUT", 5)) &&
      (p = strchr(buf, '('))) {
    while (*++p == ' ') ;
    for (e = p; *e && *e != ' ' && *e != ')'; e++) ;
    return strdata(lj_str_new(L, p, e-p));
  }
  return NULL;
}

/* Quick and dirty solution to resolve shared library name from ld script. */
static const char *clib_resolve_lds(lua_State *L, const char *name)
{
  FILE *fp = fopen(name, "r");
  const char *p = NULL;
  if (fp) {
    char buf[256];
    if (fgets(buf, sizeof(buf), fp)) {
      if (!strncmp(buf, "/* GNU ld script", 16)) {  /* ld script magic? */
	while (fgets(buf, sizeof(buf), fp)) {  /* Check all lines. */
	  p = clib_check_lds(L, buf);
	  if (p) break;
	}
      } else {  /* Otherwise check only the first line. */
	p = clib_check_lds(L, buf);
      }
    }
    fclose(fp);
  }
  return p;
}

static void *clib_loadlib(lua_State *L, const char *name, int global)
{
  void *h = dlopen(clib_extname(L, name),
		   RTLD_LAZY | (global?RTLD_GLOBAL:RTLD_LOCAL));
  if (!h) {
    const char *e, *err = dlerror();
    if (err && *err == '/' && (e = strchr(err, ':')) &&
	(name = clib_resolve_lds(L, strdata(lj_str_new(L, err, e-err))))) {
      h = dlopen(name, RTLD_LAZY | (global?RTLD_GLOBAL:RTLD_LOCAL));
      if (h) return h;
      err = dlerror();
    }
    if (!err) err = "dlopen failed";
    lj_err_callermsg(L, err);
  }
  return h;
}

static void clib_unloadlib(CLibrary *cl)
{
  if (cl->handle && cl->handle != CLIB_DEFHANDLE)
    dlclose(cl->handle);
}

#elif LJ_TARGET_WINDOWS

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS	4
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT	2
BOOL WINAPI GetModuleHandleExA(DWORD, LPCSTR, HMODULE*);
#endif

#define CLIB_DEFHANDLE	((void *)-1)

/* Default libraries. */
enum {
  CLIB_HANDLE_EXE,
#if !LJ_TARGET_UWP
  CLIB_HANDLE_DLL,
  CLIB_HANDLE_CRT,
  CLIB_HANDLE_KERNEL32,
  CLIB_HANDLE_USER32,
  CLIB_HANDLE_GDI32,
#endif
  CLIB_HANDLE_MAX
};

static void *clib_def_handle[CLIB_HANDLE_MAX];

LJ_NORET LJ_NOINLINE static void clib_error(lua_State *L, const char *fmt,
					    const char *name)
{
  DWORD err = GetLastError();
#if LJ_TARGET_XBOXONE
  wchar_t wbuf[128];
  char buf[128*2];
  if (!FormatMessageW(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_SYSTEM,
		      NULL, err, 0, wbuf, sizeof(wbuf)/sizeof(wchar_t), NULL) ||
      !WideCharToMultiByte(CP_ACP, 0, wbuf, 128, buf, 128*2, NULL, NULL))
#else
  char buf[128];
  if (!FormatMessageA(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_SYSTEM,
		      NULL, err, 0, buf, sizeof(buf), NULL))
#endif
    buf[0] = '\0';
  lj_err_callermsg(L, lj_strfmt_pushf(L, fmt, name, buf));
}

static int clib_needext(const char *s)
{
  while (*s) {
    if (*s == '/' || *s == '\\' || *s == '.') return 0;
    s++;
  }
  return 1;
}

static const char *clib_extname(lua_State *L, const char *name)
{
  if (clib_needext(name)) {
    name = lj_strfmt_pushf(L, "%s.dll", name);
    L->top--;
  }
  return name;
}

static void *clib_loadlib(lua_State *L, const char *name, int global)
{
  DWORD oldwerr = GetLastError();
  void *h = LJ_WIN_LOADLIBA(clib_extname(L, name));
  if (!h) clib_error(L, "cannot load module " LUA_QS ": %s", name);
  SetLastError(oldwerr);
  UNUSED(global);
  return h;
}

static void clib_unloadlib(CLibrary *cl)
{
  if (cl->handle == CLIB_DEFHANDLE) {
#if !LJ_TARGET_UWP
    MSize i;
    for (i = CLIB_HANDLE_KERNEL32; i < CLIB_HANDLE_MAX; i++) {
      void *h = clib_def_handle[i];
      if (h) {
	clib_def_handle[i] = NULL;
	FreeLibrary((HINSTANCE)h);
      }
    }
#endif
  } else if (cl->handle) {
    FreeLibrary((HINSTANCE)cl->handle);
  }
}

#if LJ_TARGET_UWP
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#endif

#else

#define CLIB_DEFHANDLE	NULL

LJ_NORET LJ_NOINLINE static void clib_error(lua_State *L, const char *fmt,
					    const char *name)
{
  lj_err_callermsg(L, lj_strfmt_pushf(L, fmt, name, "no support for this OS"));
}

static void *clib_loadlib(lua_State *L, const char *name, int global)
{
  lj_err_callermsg(L, "no support for loading dynamic libraries for this OS");
  UNUSED(name); UNUSED(global);
  return NULL;
}

static void clib_unloadlib(CLibrary *cl)
{
  UNUSED(cl);
}

#endif

/* -- C library indexing -------------------------------------------------- */

#if LJ_TARGET_X86 && LJ_ABI_WIN
/* Compute argument size for fastcall/stdcall functions. */
static CTSize clib_func_argsize(CTState *cts, CType *ct)
{
  CTSize n = 0;
  while (ct->sib) {
    CType *d;
    ct = ctype_get(cts, ct->sib);
    if (ctype_isfield(ct->info)) {
      d = ctype_rawchild(cts, ct);
      n += ((d->size + 3) & ~3);
    }
  }
  return n;
}
#endif

/* Get redirected or mangled external symbol. */
static const char *clib_extsym(CTState *cts, CType *ct, GCstr *name)
{
  if (ct->sib) {
    CType *ctf = ctype_get(cts, ct->sib);
    if (ctype_isxattrib(ctf->info, CTA_REDIR))
      return strdata(gco2str(gcref(ctf->name)));
  }
  return strdata(name);
}

/* C librarys function */
typedef struct CLibraryHandle {
    int global;
    char *name;
    void *handle;
} CLibraryHandle;
#define CLibraryHandleName(__clh) ((__clh)->name ? (__clh)->name : "DEFAULTE")
#define CLibraryHandleGlobal(__clh) ((__clh)->global ? "true" : "false")
#define CLibraryHandleHandle(__clh) ((__clh)->handle)
#define CLibraryHandlePtr(__clh) (__clh)
#define CLibraryHandleAllFormat " name:%s, global:%s, clh(%p, handle:%p)"
#define CLibraryHandleAll(__clh) CLibraryHandleName(__clh), \
    CLibraryHandleGlobal(__clh), CLibraryHandlePtr(__clh), \
    CLibraryHandleHandle(__clh)

static CLibraryHandle *
clibh_new(lua_State *L, int global, GCstr *name)
{
    CLibraryHandle *clh = lj_mem_newt(L,
            sizeof(CLibraryHandle), CLibraryHandle);
    clh->global = global;
    if (name == NULL) {
        clh->name = NULL;
        clh->handle = CLIB_DEFHANDLE;
    } else {
        const char *clname = strdata(name);
        MSize slen = strlen(clname);
        clh->name = lj_mem_newt(L, (slen+1), char);
        strcpy(clh->name, clname);
        clh->name[slen] = '\0';
        clh->handle = clib_loadlib(L, clname, global);
    }
    LJ_LOGF("new C library. L:%p" CLibraryHandleAllFormat,
            L, CLibraryHandleAll(clh));
    return clh;
}

static void
clibh_free(lua_State *L, CLibraryHandle *clh)
{
    LJ_LOGF("free C library. L:%p" CLibraryHandleAllFormat,
            L, CLibraryHandleAll(clh));
    global_State *g = G(L);
    if ((clh->handle != NULL) &&
            (clh->handle != CLIB_DEFHANDLE)) {
        dlclose(clh->handle);
        clh->handle = NULL;
    }
    if (clh->name != NULL) {
        lj_mem_free(g, clh->name, strlen(clh->name)+1);
    }
    lj_mem_free(g, clh, sizeof(*clh));
}

typedef struct CLibrarys {
    GCtab *cache;
    MSize maxcnt;
    MSize cnt;
    CLibraryHandle **handles;
    CLibraryHandle *dhandle; /* Default C Library handle */
} CLibrarys;

static void
clibs_extend(lua_State *L, CLibrarys *cls)
{
    MSize maxcnt, idx;
    if (cls->maxcnt == 0) {
        maxcnt = 8;
    } else {
        maxcnt = cls->maxcnt + 4;
    }
    cls->handles = lj_mem_realloc(L, cls->handles,
            (cls->maxcnt * sizeof(CLibraryHandle*)),
            (maxcnt * sizeof(CLibraryHandle*)));
    for (idx = cls->maxcnt; idx < maxcnt; ++idx) {
        cls->handles[idx] = NULL;
    }
    cls->maxcnt = maxcnt;
}

static CLibrarys *
clibs_new(lua_State *L)
{
    CLibrarys *cls = lj_mem_newt(L, sizeof(CLibrarys), CLibrarys);
    cls->cache = lj_tab_new(L, 0, 0);
    cls->cnt = 0;
    cls->maxcnt = 0;
    cls->dhandle = NULL;
    clibs_extend(L, cls);
    return cls;
}

static void
clibs_free(lua_State *L, CLibrarys *cls)
{
    global_State *g = G(L);
    MSize idx;
    for (idx = 0; idx < cls->cnt; ++idx) {
        clibh_free(L, cls->handles[idx]);
        cls->handles[idx] = NULL;
    }
    lj_mem_free(g, cls, sizeof(*cls));
}

static CLibraryHandle *
clibs_find(CLibrarys *cls, int global, GCstr *name)
{
    if (name == NULL) {
        return cls->dhandle;
    } else {
        CLibraryHandle *clh;
        MSize idx;
        for (idx = 0; idx < cls->cnt; ++idx) {
            clh = cls->handles[idx];
            if (((!!global) == (!!(clh->global))) &&
                    (strcmp(clh->name, strdata(name)) == 0)) {
                return clh;
            }
        }
    }
    return NULL;
}

static void
clibs_add(lua_State *L, CLibrarys *cls, int global, GCstr *name)
{
    CLibraryHandle *clh = clibs_find(cls, global, name);
    if (clh == NULL) {
        clh = clibh_new(L, global, name);
        if (name == NULL) {
            cls->dhandle = clh;
        } else {
            if (cls->cnt == cls->maxcnt) {
                clibs_extend(L, cls);
            }
            cls->handles[cls->cnt++] = clh;
        }
    }
    LJ_LOGF("add C library. L:%p" CLibraryHandleAllFormat,
            L, CLibraryHandleAll(clh));
}

static void *
clibs_getsym(lua_State *L, CLibrarys *cls, const char *name)
{
    CLibraryHandle *clh;
    void *sym = NULL;
    MSize idx;
    for (idx = 0; idx < cls->cnt; ++idx) {
        clh = cls->handles[idx];
        sym = dlsym(clh->handle, name);
        if (sym != NULL) {
            break;
        }
    }
    if (sym == NULL) {
        clh = cls->dhandle;
        sym = dlsym(clh->handle, name);
    }
    LJ_LOGF("get symbol(%s:%p). L:%p" CLibraryHandleAllFormat,
            name, sym, L, CLibraryHandleAll(clh));
    return sym;
}

static TValue *
clibs_index(lua_State *L, CLibrarys *cls, GCstr *name)
{
    TValue *tv = lj_tab_setstr(L, cls->cache, name);
    if (LJ_UNLIKELY(tvisnil(tv))) {
        CTState *cts = ctype_cts(L);
        CType *ct;
        CTypeID id = lj_ctype_getname(cts, &ct, name, CLNS_INDEX);
        if (!id) {
            lj_err_callerv(L, LJ_ERR_FFI_NODECL, strdata(name));
        }
        if (ctype_isconstval(ct->info)) {
            CType *ctt = ctype_child(cts, ct);
            lj_assertCTS(ctype_isinteger(ctt->info) && ctt->size <= 4,
                    "only 32 bit const supported");  /* NYI */
            if ((ctt->info & CTF_UNSIGNED) && (int32_t)ct->size < 0)
                setnumV(tv, (lua_Number)(uint32_t)ct->size);
            else
                setintV(tv, (int32_t)ct->size);
        } else {
            const char *sym = clib_extsym(cts, ct, name);
#if LJ_TARGET_WINDOWS
            DWORD oldwerr = GetLastError();
#endif
            void *p = clibs_getsym(L, cls, sym);
            GCcdata *cd;
            lj_assertCTS(ctype_isfunc(ct->info) || ctype_isextern(ct->info),
                    "unexpected ctype %08x in clib", ct->info);
#if LJ_TARGET_X86 && LJ_ABI_WIN
            /* Retry with decorated name for fastcall/stdcall functions. */
            if (!p && ctype_isfunc(ct->info)) {
	            CTInfo cconv = ctype_cconv(ct->info);
	            if (cconv == CTCC_FASTCALL || cconv == CTCC_STDCALL) {
	                CTSize sz = clib_func_argsize(cts, ct);
	                const char *symd = lj_strfmt_pushf(L,
                            cconv == CTCC_FASTCALL ? "@%s@%d" : "_%s@%d",
                            sym, sz);
	                L->top--;
                    p = clibs_getsym(L, cls, symd);
                }
            }
#endif
            if (!p) {
                clib_error(L, "cannot resolve symbol " LUA_QS ": %s", sym);
            }
#if LJ_TARGET_WINDOWS
            SetLastError(oldwerr);
#endif
            cd = lj_cdata_new(cts, id, CTSIZE_PTR);
            *(void **)cdataptr(cd) = p;
            setcdataV(L, tv, cd);
            lj_gc_anybarriert(L, cls->cache);
        }
    }
    LJ_LOGF("index symbol(%s, tv:%p). L:%p", strdata(name), tv, L);
    return tv;
}

/* Index a C library by name. */
TValue *lj_clib_index(lua_State *L, CLibrary *cl, GCstr *name)
{
    (void)cl;
    return clibs_index(L, (CLibrarys *)(L->clibs), name);
}

/* -- C library management ------------------------------------------------ */

/* Create a new CLibrary object and push it on the stack. */
static CLibrary *clib_new(lua_State *L, GCtab *mt)
{
  GCtab *t = lj_tab_new(L, 0, 0);
  GCudata *ud = lj_udata_new(L, sizeof(CLibrary), t);
  CLibrary *cl = (CLibrary *)uddata(ud);
  cl->cache = t;
  ud->udtype = UDTYPE_FFI_CLIB;
  /* NOBARRIER: The GCudata is new (marked white). */
  setgcref(ud->metatable, obj2gco(mt));
  setudataV(L, L->top++, ud);
  return cl;
}

/* Load a C library. */
void lj_clib_load(lua_State *L, GCtab *mt, GCstr *name, int global)
{
  clibs_add(L, (CLibrarys *)(L->clibs), global, name);
  CLibrary *cl = clib_new(L, mt);
  cl->handle = NULL;
}

/* Unload a C library. */
void lj_clib_unload(CLibrary *cl)
{
  clib_unloadlib(cl);
  cl->handle = NULL;
}

/* Create the default C library object. */
void lj_clib_default(lua_State *L, GCtab *mt)
{
  clibs_add(L, (CLibrarys *)(L->clibs), 1, NULL);
  CLibrary *cl = clib_new(L, mt);
  cl->handle = CLIB_DEFHANDLE;
}

void
lj_clibs_create(lua_State *L)
{
    L->clibs = (void *)clibs_new(L);
    LJ_LOGF("CLibrarys object create. L:%p, L->clibs:%p", L, L->clibs);
}

void
lj_clibs_destroy(lua_State *L)
{
    LJ_LOGF("CLibrarys object destroy. L:%p, L->clibs:%p", L, L->clibs);
    if (L->clibs != NULL) {
        clibs_free(L, (CLibrarys *)(L->clibs));
        L->clibs = NULL;
    }
}

#endif
