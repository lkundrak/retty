/* retty.c - attach process to current terminal
 *
 * Usage: retty PID
 *
 * PID is the pid of a running process.
 *
 * retty works on x86 Linux.
 *
 * Copyright (c) 2006  Petr Baudis, Jan Sembera
 *
 * Symbol resolver code:
 * Copyright (c) 2002  Victor Zandy <zandy@cs.wisc.edu>
 */


#define _XOPEN_SOURCE 500  /* include pread,pwrite */
#define _GNU_SOURCE
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

unsigned long openaddr = 0xabcdef, dupaddr, dup2addr, ioctladdr, raiseaddr, closeaddr;


/* memory map for libraries */
#define MAX_NAME_LEN 256
#define MEMORY_ONLY  "[memory]"
struct mm {
	char name[MAX_NAME_LEN];
	unsigned long start, end;
};

typedef struct symtab *symtab_t;
struct symlist {
	Elf32_Sym *sym;       /* symbols */
	char *str;            /* symbol strings */
	unsigned num;         /* number of symbols */
};
struct symtab {
	struct symlist *st;    /* "static" symbols */
	struct symlist *dyn;   /* dynamic symbols */
};

static void * 
xmalloc(size_t size)
{
	void *p;
	p = malloc(size);
	if (!p) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	return p;
}

static struct symlist *
get_syms(int fd, Elf32_Shdr *symh, Elf32_Shdr *strh)
{
	struct symlist *sl, *ret;
	int rv;

	ret = NULL;
	sl = (struct symlist *) xmalloc(sizeof(struct symlist));
	sl->str = NULL;
	sl->sym = NULL;

	/* sanity */
	if (symh->sh_size % sizeof(Elf32_Sym)) { 
		fprintf(stderr, "elf_error\n");
		goto out;
	}

	/* symbol table */
	sl->num = symh->sh_size / sizeof(Elf32_Sym);
	sl->sym = (Elf32_Sym *) xmalloc(symh->sh_size);
	rv = pread(fd, sl->sym, symh->sh_size, symh->sh_offset);
	if (0 > rv) {
		perror("read");
		goto out;
	}
	if (rv != symh->sh_size) {
		fprintf(stderr, "elf error\n");
		goto out;
	}

	/* string table */
	sl->str = (char *) xmalloc(strh->sh_size);
	rv = pread(fd, sl->str, strh->sh_size, strh->sh_offset);
	if (0 > rv) {
		perror("read");
		goto out;
	}
	if (rv != strh->sh_size) {
		fprintf(stderr, "elf error");
		goto out;
	}

	ret = sl;
out:
	return ret;
}

static int
do_load(int fd, symtab_t symtab)
{
	int rv;
	size_t size;
	Elf32_Ehdr ehdr;
	Elf32_Shdr *shdr = NULL, *p;
	Elf32_Shdr *dynsymh, *dynstrh;
	Elf32_Shdr *symh, *strh;
	char *shstrtab = NULL;
	int i;
	int ret = -1;
	
	/* elf header */
	rv = read(fd, &ehdr, sizeof(ehdr));
	if (0 > rv) {
		perror("read");
		goto out;
	}
	if (rv != sizeof(ehdr)) {
		fprintf(stderr, "elf error\n");
		goto out;
	}
	if (strncmp(ELFMAG, ehdr.e_ident, SELFMAG)) { /* sanity */
		fprintf(stderr, "not an elf\n");
		goto out;
	}
	if (sizeof(Elf32_Shdr) != ehdr.e_shentsize) { /* sanity */
		fprintf(stderr, "elf error\n");
		goto out;
	}

	/* section header table */
	size = ehdr.e_shentsize * ehdr.e_shnum;
	shdr = (Elf32_Shdr *) xmalloc(size);
	rv = pread(fd, shdr, size, ehdr.e_shoff);
	if (0 > rv) {
		perror("read");
		goto out;
	}
	if (rv != size) {
		fprintf(stderr, "elf error");
		goto out;
	}
	
	/* section header string table */
	size = shdr[ehdr.e_shstrndx].sh_size;
	shstrtab = (char *) xmalloc(size);
	rv = pread(fd, shstrtab, size, shdr[ehdr.e_shstrndx].sh_offset);
	if (0 > rv) {
		perror("read");
		goto out;
	}
	if (rv != size) {
		fprintf(stderr, "elf error\n");
		goto out;
	}

	/* symbol table headers */
	symh = dynsymh = NULL;
	strh = dynstrh = NULL;
	for (i = 0, p = shdr; i < ehdr.e_shnum; i++, p++)
		if (SHT_SYMTAB == p->sh_type) {
			if (symh) {
				fprintf(stderr, "too many symbol tables\n");
				goto out;
			}
			symh = p;
		} else if (SHT_DYNSYM == p->sh_type) {
			if (dynsymh) {
				fprintf(stderr, "too many symbol tables\n");
				goto out;
			}
			dynsymh = p;
		} else if (SHT_STRTAB == p->sh_type
			   && !strncmp(shstrtab+p->sh_name, ".strtab", 7)) {
			if (strh) {
				fprintf(stderr, "too many string tables\n");
				goto out;
			}
			strh = p;
		} else if (SHT_STRTAB == p->sh_type
			   && !strncmp(shstrtab+p->sh_name, ".dynstr", 7)) {
			if (dynstrh) {
				fprintf(stderr, "too many string tables\n");
				goto out;
			}
			dynstrh = p;
		}
	/* sanity checks */
	if ((!dynsymh && dynstrh) || (dynsymh && !dynstrh)) {
		fprintf(stderr, "bad dynamic symbol table");
		goto out;
	}
	if ((!symh && strh) || (symh && !strh)) {
		fprintf(stderr, "bad symbol table");
		goto out;
	}
	if (!dynsymh && !symh) {
		fprintf(stderr, "no symbol table");
		goto out;
	}

	/* symbol tables */
	if (dynsymh)
		symtab->dyn = get_syms(fd, dynsymh, dynstrh);
	if (symh)
		symtab->st = get_syms(fd, symh, strh);
	ret = 0;
out:
	free(shstrtab);
	free(shdr);
	return ret;
}

static symtab_t
load_symtab(char *filename)
{
	int fd;
	symtab_t symtab;

	symtab = (symtab_t) xmalloc(sizeof(*symtab));
	memset(symtab, 0, sizeof(*symtab));

	fd = open(filename, O_RDONLY);
	if (0 > fd) {
		perror("open");
		return NULL;
	}
	if (0 > do_load(fd, symtab)) {
		fprintf(stderr, "Error ELF parsing %s\n", filename);
		free(symtab);
		symtab = NULL;
	}
	close(fd);
	return symtab;
}


static int
load_memmap(pid_t pid, struct mm *mm, int *nmmp)
{
	char raw[10000];
	char name[MAX_NAME_LEN];
	char *p;
	unsigned long start, end;
	struct mm *m;
	int nmm = 0;
	int fd, rv;
	int i;

	sprintf(raw, "/proc/%d/maps", pid);
	fd = open(raw, O_RDONLY);
	if (0 > fd) {
		fprintf(stderr, "Can't open %s for reading\n", raw);
		return -1;
	}

	/* Zero to ensure data is null terminated */
	memset(raw, 0, sizeof(raw));

	p = raw;
	while (1) {
		rv = read(fd, p, sizeof(raw)-(p-raw));
		if (0 > rv) {
			perror("read");
			return -1;
		}
		if (0 == rv)
			break;
		p += rv;
		if (p-raw >= sizeof(raw)) {
			fprintf(stderr, "Too many memory mapping\n");
			return -1;
		}
	}
	close(fd);

	p = strtok(raw, "\n");
	m = mm;
	while (p) {
		/* parse current map line */
		rv = sscanf(p, "%08lx-%08lx %*s %*s %*s %*s %s\n",
			    &start, &end, name);
		p = strtok(NULL, "\n");

		if (rv == 2) {
			m = &mm[nmm++];
			m->start = start;
			m->end = end;
			strcpy(m->name, MEMORY_ONLY);
			continue;
		}

		/* search backward for other mapping with same name */
		for (i = nmm-1; i >= 0; i--) {
			m = &mm[i];
			if (!strcmp(m->name, name))
				break;
		}

		if (i >= 0) {
			if (start < m->start)
				m->start = start;
			if (end > m->end)
				m->end = end;
		} else {
			/* new entry */
			m = &mm[nmm++];
			m->start = start;
			m->end = end;
			strcpy(m->name, name);
		}
	}
	*nmmp = nmm;
	return 0;
}

/* Find libc in MM, storing no more than LEN-1 chars of
   its name in NAME and set START to its starting
   address.  If libc cannot be found return -1 and
   leave NAME and START untouched.  Otherwise return 0
   and null-terminated NAME. */
static int
find_libc(char *name, int len, unsigned long *start,
	  struct mm *mm, int nmm)
{
	int i;
	struct mm *m;
	char *p;
	for (i = 0, m = mm; i < nmm; i++, m++) {
		if (!strcmp(m->name, MEMORY_ONLY))
			continue;
		p = strrchr(m->name, '/');
		if (!p)
			continue;
		p++;
		if (strncmp("libc", p, 4))
			continue;
		p += 4;

		/* here comes our crude test -> 'libc.so' or 'libc-[0-9]' */
		if (!strncmp(".so", p, 3) || (p[0] == '-' && isdigit(p[1])))
			break;
	}
	if (i >= nmm)
		/* not found */
		return -1;

	*start = m->start;
	strncpy(name, m->name, len);
	if (strlen(m->name) >= len)
		name[len-1] = '\0';
	return 0;
}

static int
lookup2(struct symlist *sl, unsigned char type,
	char *name, unsigned long *val)
{
	Elf32_Sym *p;
	int len;
	int i;

	len = strlen(name);
	for (i = 0, p = sl->sym; i < sl->num; i++, p++) {
		if (!strcmp(sl->str+p->st_name, name) 
		    && ELF32_ST_TYPE(p->st_info) == type) {
			*val = p->st_value;
			return 0;
		}
	}
	return -1;
}

static int
lookup_sym(symtab_t s, unsigned char type,
	   char *name, unsigned long *val)
{
	if (s->dyn && !lookup2(s->dyn, type, name, val))
		return 0;
	if (s->st && !lookup2(s->st, type, name, val))
		return 0;
	return -1;
}

static int
lookup_func_sym(symtab_t s, char *name, unsigned long *val)
{
	return lookup_sym(s, STT_FUNC, name, val);
}

static int
finddlopen(pid_t pid)
{
	struct mm mm[50];
	unsigned long libcaddr = 0x111111;
	int nmm;
	char libc[256];
	symtab_t s;

	if (0 > load_memmap(pid, mm, &nmm)) {
		fprintf(stderr, "cannot read memory map\n");
		return -1;
	}
	if (0 > find_libc(libc, sizeof(libc), &libcaddr, mm, nmm)) {
		fprintf(stderr, "cannot find libc\n");
		return -1;
	}
	s = load_symtab(libc);
	if (!s) {
		fprintf(stderr, "cannot read symbol table\n");
		return -1;
	}
#define l(n_, s_) \
	if (0 > lookup_func_sym(s, n_, &s_)) { \
		fprintf(stderr, "cannot find "n_"\n"); \
		return -1; \
	} \
	s_ += libcaddr; \
	//printf("%s: %lx <- libc: %lx\n", n_, s_, libcaddr);
	l("open", openaddr);
	l("dup", dupaddr);
	l("dup2", dup2addr);
	l("raise", raiseaddr);
	l("ioctl", ioctladdr);
	l("close", closeaddr);
	return 0;
}

/* Write NLONG 4 byte words from BUF into PID starting
   at address POS.  Calling process must be attached to PID. */
static int
write_mem(pid_t pid, unsigned long *buf, int nlong, unsigned long pos)
{
	unsigned long *p;
	int i;

	for (p = buf, i = 0; i < nlong; p++, i++)
		if (0 > ptrace(PTRACE_POKEDATA, pid, pos+(i*4), *p))
			return -1;
	return 0;
}

static char code[] = {
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
	0x90,
/* 3+1:*/ 0x60,						/* pushad */
/*  0: */ 0x55,						/* push   %ebp */
/*  1: */ 0x89, 0xe5,					/* mov    %esp,%ebp */
/*  3: */ 0x83, 0xec, 0x68,				/* sub    $0x18,%esp */

/**   6:**/	0xc7, 0x44, 0x24, 0x04, 0x02, 0x00, 0x00,0x00, // 	movl   $0x2,0x4(%esp)
/**   e:**/	0x8b, 0x45, 0x24,             //	mov    0x8(%ebp),%eax
/**  11:**/	0x89, 0x04, 0x24,             //	mov    %eax,(%esp)
/**  14:**/	0xe8, 0xfc, 0xff, 0xff, 0xff,   //    	call   15 <injected+0x15>

/**  19:**/	0x89, 0x45, 0xf4,             //	mov    %eax,0xfffffffc(%ebp)
/*  6: */ 0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	/* movl   $0x0,(%esp) */
/*  d: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,			/* call   e <injected+0xe> */

/* 12: */ 0x89, 0x45, 0xf0,				/* mov    %eax,0xfffffffc(%ebp) */
/* 15: */ 0xc7, 0x04, 0x24, 0x01, 0x00, 0x00, 0x00,	/* movl   $0x1,(%esp) */
/* 1c: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,			/* call   1d <injected+0x1d> */

/* 21: */ 0x89, 0x45, 0xec,				/* mov    %eax,0xfffffff8(%ebp) */
/* 24: */ 0xc7, 0x04, 0x24, 0x02, 0x00, 0x00, 0x00,	/* movl   $0x2,(%esp) */
/* 2b: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,			/* call   2c <injected+0x2c> */

/* 30: */ 0x89, 0x45, 0xe8,				/* mov    %eax,0xfffffff4(%ebp) */
/* 33: */ 0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	/* movl   $0x0,(%esp) */
/* 3a: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,			/* call   3b <injected+0x3b> */

/* 3f: */ 0xc7, 0x04, 0x24, 0x01, 0x00, 0x00, 0x00,	/* movl   $0x1,(%esp) */
/* 46: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,			/* call   47 <injected+0x47> */

/* 4b: */ 0xc7, 0x04, 0x24, 0x02, 0x00, 0x00, 0x00,	/* movl   $0x2,(%esp) */
/* 52: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,			/* call   53 <injected+0x53> */

/* 57: */ 0xc7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00,0x00,/* movl   $0x0,0x4(%esp) */
/* 5f: */ 0x8b, 0x45, 0xf4,				/* mov    0x8(%ebp),%eax */
/* 62: */ 0x89, 0x04, 0x24,				/* mov    %eax,(%esp) */
/* 65: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,			/* call   66 <injected+0x66> */

/* 6a: */ 0xc7, 0x44, 0x24, 0x04, 0x01, 0x00, 0x00,0x00,/* movl   $0x1,0x4(%esp) */
/* 72: */ 0x8b, 0x45, 0xf4,				/* mov    0x8(%ebp),%eax */
/* 75: */ 0x89, 0x04, 0x24,				/* mov    %eax,(%esp) */
/* 78: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,			/* call   79 <injected+0x79> */

/* 7d: */ 0xc7, 0x44, 0x24, 0x04, 0x02, 0x00, 0x00,0x00,/* movl   $0x2,0x4(%esp) */
/* 85: */ 0x8b, 0x45, 0xf4,				/* mov    0x8(%ebp),%eax */
/* 88: */ 0x89, 0x04, 0x24,				/* mov    %eax,(%esp) */
/* 8b: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,			/* call   8c <injected+0x8c> */

/* a6:  */ 0x8b, 0x45, 0xf4, // mov    0xfffffff4(%ebp),%eax
/* a9:  */ 0x89, 0x04, 0x24, // mov    %eax,(%esp)
/* ac:  */ 0xe8, 0xfc, 0xff, 0xff, 0xff,         // call   ad <injected+0xad>

/* b1:  */ 0x8d, 0x45, 0xa8, // lea    0xffffffa8(%ebp),%eax
/* b4:  */ 0x89, 0x44, 0x24, 0x08, // mov    %eax,0x8(%esp)
/* b8:  */ 0xc7, 0x44, 0x24, 0x04, 0x01, 0x54, 0x00, 0x00,   // movl   $0x5401,0x4(%esp)
/* c0:  */ 0x8b, 0x45, 0xf0, // mov    0xfffffff0(%ebp),%eax
/* c3:  */ 0x89, 0x04, 0x24, // mov    %eax,(%esp)
/* c6:  */ 0xe8, 0xfc, 0xff, 0xff, 0xff,         // call   c7 <injected+0xc7>

/* cb:  */ 0x8d, 0x45, 0xa8, // lea    0xffffffa8(%ebp),%eax
/* ce:  */ 0x89, 0x44, 0x24, 0x08, // mov    %eax,0x8(%esp)
/* d2:  */ 0xc7, 0x44, 0x24, 0x04, 0x02, 0x54, 0x00, 0x00,   // movl   $0x5402,0x4(%esp)
/* da:  */ 0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,   // movl   $0x0,(%esp)
/* e1:  */ 0xe8, 0xfc, 0xff, 0xff, 0xff,         // call   e2 <injected+0xe2>

/* e6:  */ 0x8d, 0x45, 0xa8, // lea    0xffffffa8(%ebp),%eax
/* e9:  */ 0x89, 0x44, 0x24, 0x08, // mov    %eax,0x8(%esp)
/* ed:  */ 0xc7, 0x44, 0x24, 0x04, 0x01, 0x54, 0x00, 0x00,   // movl   $0x5401,0x4(%esp)
/* f5:  */ 0x8b, 0x45, 0xec, // mov    0xffffffec(%ebp),%eax
/* f8:  */ 0x89, 0x04, 0x24, // mov    %eax,(%esp)
/* fb:  */ 0xe8, 0xfc, 0xff, 0xff, 0xff,         // call   fc <injected+0xfc>

/* 100: */ 0x8d, 0x45, 0xa8, // lea    0xffffffa8(%ebp),%eax
/* 103: */ 0x89, 0x44, 0x24, 0x08, // mov    %eax,0x8(%esp)
/* 107: */ 0xc7, 0x44, 0x24, 0x04, 0x02, 0x54, 0x00, 0x00,   // movl   $0x5402,0x4(%esp)
/* 10f: */ 0xc7, 0x04, 0x24, 0x01, 0x00, 0x00, 0x00,   // movl   $0x1,(%esp)
/* 116: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,         // call   117 <injected+0x117>

/* 11b: */ 0x8d, 0x45, 0xa8, // lea    0xffffffa8(%ebp),%eax
/* 11e: */ 0x89, 0x44, 0x24, 0x08, // mov    %eax,0x8(%esp)
/* 122: */ 0xc7, 0x44, 0x24, 0x04, 0x01, 0x54, 0x00, 0x00,   // movl   $0x5401,0x4(%esp)
/* 12a: */ 0x8b, 0x45, 0xe8, // mov    0xffffffe8(%ebp),%eax
/* 12d: */ 0x89, 0x04, 0x24, // mov    %eax,(%esp)
/* 130: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,         // call   131 <injected+0x131>

/* 135: */ 0x8d, 0x45, 0xa8, // lea    0xffffffa8(%ebp),%eax
/* 138: */ 0x89, 0x44, 0x24, 0x08, // mov    %eax,0x8(%esp)
/* 13c: */ 0xc7, 0x44, 0x24, 0x04, 0x02, 0x54, 0x00, 0x00,   // movl   $0x5402,0x4(%esp)
/* 144: */ 0xc7, 0x04, 0x24, 0x02, 0x00, 0x00, 0x00,   // movl   $0x2,(%esp)
/* 14b: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,         // call   14c <injected+0x14c>


/* 90: */ 0xc7, 0x04, 0x24, 0x1c, 0x00, 0x00, 0x00,	/* movl   $0x1c,(%esp) */
/* 97: */ 0xe8, 0xfc, 0xff, 0xff, 0xff,			/* call   98 <injected+0x98> */
/* 9c: */ 0xc9,						/* leave */
/* 9c+1:*/ 0x61,					/* popad */
///*  3: */ 0x83, 0xc4, 0x00,				/* sub    $0x18,%esp */ // sizeof(code)+
//0x81, 0xec, 0x00, 0x00, 0x00, 0x00,//sizeof(code)+n+4
0x81, 0xc4, 0x00, 0x00, 0x00, 0x00,//sizeof(code)+n+4
/* 9d: */ 0xc3,						/* ret */
0x00,0x00
};

int oopen[] = {0x16-7};
int odup[] = {0x1e, 0x2d, 0x3c};
int oclose[] = {0x4b, 0x57, 0x63, 0xae - 0x7};
int odup2[] = {0x76, 0x89, 0x9c};
int oioctl[] = {0xc8-7, 0xe3-7, 0xfd-7, 0x118-7, 0x132-7, 0x14d-7};
int oraise[] = {0x159-7};

#define rewrite(code, offsets, value) rewrite_(code, offsets, sizeof(offsets)/sizeof(*offsets), value)
void
rewrite_(char code[], int offsets[], int n_offsets, unsigned long value)
{
	int i;
	for (i = 0; i < n_offsets; i++) {
		/* :) */
		unsigned long *p = (unsigned long *) &code[23+offsets[i]];
		*p = value - (23+offsets[i]) - 4;
#if 0
		printf("[%x] %lx\n", 7+offsets[i], value);
		printf("\t");
		for (j = -1; j < 6; j++)
			printf("%x ", (int)code[7+offsets[i]+j]);
		printf("\n");
#endif
	}
}

int ptm;

void
sigwinch(int x)
{
	struct winsize w;
	ioctl(1, TIOCGWINSZ, &w);
	ioctl(ptm, TIOCSWINSZ, &w);
}

ssize_t
process_escapes(char *buf, ssize_t *len)
{
	static enum { ST_NONE, ST_ENTER, ST_ESCAPE } state;
	ssize_t i;
	for (i = 0; i < *len; i++) {
		//fprintf(stderr, "[state=%d %d/%d char=%x]\n", state, i, *len - 1, buf[i]);
		switch (state) {
		case ST_NONE:
			if (buf[i] == '\n' || buf[i] == '\r')
				state = ST_ENTER;
			break;
		case ST_ENTER:
			if (buf[i] == '`') {
				state = ST_ESCAPE;
				memmove(buf + i, buf + i + 1, *len - i - 1);
				(*len)--; i--;
			} else {
				state = ST_NONE;
			}
			break;
		case ST_ESCAPE:
			state = ST_NONE;
			switch (buf[i]) {
			case '.':
				return i-2+1;
			case '?':
				printf("Supported escape sequences:\n");
				printf("`. - return the process to its original terminal\n");
				printf("`? - this message\n");
				printf("`` - send the escape character by typing it twice\n");
				printf("(Note that escapes are only recognized immediately after newline.)\n");
				memmove(buf + i, buf + i + 1, *len - i - 1);
				(*len)--; i--;
				break;
			case '`':
				break;
			default:
				memmove(buf + i + 1, buf + i, *len - i);
				buf[i] = '`';
				(*len)++; i++;
				break;
			}
			break;
		}
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	pid_t pid;
	struct user_regs_struct regs;
	unsigned long codeaddr, ptsnameaddr;
	int fd, n;
	char buf[32];
	char *arg;
	char *pts;
	struct termios t_orig;

	if (argc != 2) {
		fprintf(stderr, "usage: %s PID\n", argv[0]);
		exit(1);
	}
	pid = strtol(argv[1], NULL, 0);

	if (0 > finddlopen(pid)) {
		fprintf(stderr, "parse failed\n");
		exit(1);
	}

	/* Setup pty */
	ptm = getpt();
	grantpt(ptm);
	unlockpt(ptm);
	pts = ptsname(ptm);
	tcflush(ptm, TCIOFLUSH);
	(void) ioctl(ptm, TIOCEXCL, (char *) 0);

	signal(SIGWINCH, sigwinch);

	/* Attach */
	if (0 > ptrace(PTRACE_ATTACH, pid, 0, 0)) {
		fprintf(stderr, "cannot attach to %d\n", pid);
		exit(1);
	}
	waitpid(pid, NULL, 0);
	sprintf(buf, "/proc/%d/mem", pid);
	fd = open(buf, O_WRONLY);
	if (0 > fd) {
		fprintf(stderr, "cannot open %s\n", buf);
		exit(1);
	}
	ptrace(PTRACE_GETREGS, pid, 0, &regs);

	n = strlen(pts)+1;
	n = n/4 + (n%4 ? 1 : 0);
	arg = xmalloc(n*sizeof(unsigned long));
	memcpy(arg, pts, n*4);

	/* push EIP */
	regs.esp -= 4;
	ptrace(PTRACE_POKEDATA, pid, regs.esp, regs.eip);

	/* finish code and push it */
	regs.esp -= sizeof(code);
	codeaddr = regs.esp;
	//printf("codesize: %x codeaddr: %lx\n", sizeof(code), codeaddr));
	rewrite(code, oopen, openaddr - codeaddr);
	rewrite(code, odup, dupaddr - codeaddr);
	rewrite(code, odup2, dup2addr - codeaddr);
	rewrite(code, oclose, closeaddr - codeaddr);
	rewrite(code, oioctl, ioctladdr - codeaddr);
	rewrite(code, oraise, raiseaddr - codeaddr);
	*((int*)&code[sizeof(code)-7]) = sizeof(code) + n*4 + 4;
	if (0 > write_mem(pid, (unsigned long*)&code, sizeof(code)/sizeof(long), regs.esp)) {
		fprintf(stderr, "cannot write code\n");
		exit(1);
	}

	/* push ptsname[] */
	regs.esp -= n*4;
	ptsnameaddr = regs.esp;
	if (0 > write_mem(pid, (unsigned long*)arg, n, regs.esp)) {
		fprintf(stderr, "cannot write bla argument (%s)\n",
			strerror(errno));
		exit(1);
	}

	/* push ptsname */
	regs.esp -= 4;
	ptrace(PTRACE_POKEDATA, pid, regs.esp, ptsnameaddr);

	regs.eip = codeaddr+8;
	printf("stack: %lx eip: %lx sub:%x\n", regs.esp, regs.eip, (int) code[sizeof(code)-7]);

	/* Detach and continue */
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	kill(pid, SIGWINCH); // interrupt any syscall (typically read() ;)
	sigwinch(0); // shellcode will raise another SIGWINCH after PTRACE_DETACH
	ptrace(PTRACE_DETACH, pid, 0, 0);

	ioctl(0, TCGETS, &t_orig);

	while (1) {
		struct termios t;
		fd_set fds;

		FD_ZERO(&fds);
		FD_SET(ptm, &fds);
		FD_SET(0, &fds);
		select(ptm+1, &fds, NULL, NULL, NULL);

		ioctl(ptm, TCGETS, &t);
		ioctl(0, TCSETS, &t);

		if (FD_ISSET(ptm, &fds)) {
			char buf[256];
			ssize_t len = read(ptm, buf, 256);
			if (len < 0 && errno != EINTR && errno != EAGAIN) {
				break;
			}
			write(1, buf, len);
		}

		if (FD_ISSET(0, &fds)) {
			char buf[2*256];
			ssize_t len = read(0, buf, 256);
			ssize_t stop;
			stop = process_escapes(buf, &len);
			if (stop) {
				write(ptm, buf, stop-1);
				break;
			}
			write(ptm, buf, len);
		}
	}

	ioctl(0, TCSETS, &t_orig);

	return 0;
}
