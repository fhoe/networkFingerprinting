/*
 * sc_attach : scamper driver to collect data by connecting to scamper on
 *             a specified port and supplying it with commands.
 *
 * Author    : Matthew Luckie.
 *
 */

#ifndef lint
static const char rcsid[] =
  "$Id: sc_attach.c,v 1.13 2012/04/05 18:00:55 mjl Exp $";
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <stdint.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include <assert.h>

#include "scamper_file.h"
#include "mjl_list.h"
#include "utils.h"

#define OPT_HELP        0x0001
#define OPT_INFILE      0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_STDOUT      0x0010
#define OPT_VERSION     0x0020
#define OPT_DEBUG       0x0040
#define OPT_PRIORITY    0x0080

static uint32_t               options       = 0;
static char                  *infile        = NULL;
static unsigned int           port          = 0;
static uint32_t               priority      = 1;
static int                    scamper_fd    = -1;
static int                    stdin_fd      = -1;
static char                  *readbuf       = NULL;
static size_t                 readbuf_len   = 0;
static char                  *stdinbuf      = NULL;
static size_t                 stdinbuf_len  = 0;
static char                  *outfile_name  = NULL;
static int                    outfile_fd    = -1;
static int                    data_left     = 0;
static int                    more          = 0;
static slist_t               *commands      = NULL;
static char                  *lastcommand   = NULL;
static int                    done          = 0;

static void cleanup(void)
{
  char *command;

  if(lastcommand != NULL)
    {
      free(lastcommand);
      lastcommand = NULL;
    }

  if(commands != NULL)
    {
      while((command = slist_head_pop(commands)) != NULL)
	{
	  free(command);
	}
      slist_free(commands);
      commands = NULL;
    }

  if(outfile_fd != -1)
    {
      close(outfile_fd);
      outfile_fd = -1;
    }

  if(scamper_fd != -1)
    {
      close(scamper_fd);
      scamper_fd = -1;
    }

  if(readbuf != NULL)
    {
      free(readbuf);
      readbuf = NULL;
    }

  if(stdinbuf != NULL)
    {
      free(stdinbuf);
      stdinbuf = NULL;
    }

  return;
}

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_attach [-?dv] [-i infile] [-o outfile] [-p port]\n"
	  "                 [-P priority]\n");

  if(opt_mask == 0) return;

  fprintf(stderr, "\n");

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -? give an overview of the usage of sc_attach\n");

  if(opt_mask & OPT_DEBUG)
    fprintf(stderr, "     -d output debugging information to stderr\n");

  if(opt_mask & OPT_VERSION)
    fprintf(stderr, "     -v give the version string of sc_attach\n");

  if(opt_mask & OPT_INFILE)
    fprintf(stderr, "     -i input command file\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p port to find scamper on\n");

  if(opt_mask & OPT_PRIORITY)
    fprintf(stderr, "     -P priority\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int       ch;
  long      lo;
  char     *opts = "di:o:p:P:v?";
  char     *opt_port = NULL, *opt_priority = NULL;
  uint32_t  mandatory = OPT_INFILE | OPT_OUTFILE | OPT_PORT;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'd':
	  options |= OPT_DEBUG;
	  break;

	case 'i':
	  if(strcasecmp(optarg, "-") == 0)
	    stdin_fd = STDIN_FILENO;
	  else if((options & OPT_INFILE) == 0)
	    infile = optarg;
	  else
	    return -1;
	  options |= OPT_INFILE;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  if(strcasecmp(optarg, "-") == 0)
	    options |= OPT_STDOUT;
	  else if(outfile_name == NULL)
	    outfile_name = optarg;
	  else
	    return -1;
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 'P':
	  options |= OPT_PRIORITY;
	  opt_priority = optarg;
	  break;

	case 'v':
	  printf("$Id: sc_attach.c,v 1.13 2012/04/05 18:00:55 mjl Exp $\n");
	  return -1;

	case '?':
	default:
	  usage(0xffffffff);
	  return -1;
	}
    }

  /* these options are mandatory */
  if((options & mandatory) != mandatory)
    {
      if(options == 0) usage(0);
      else             usage(mandatory);
      return -1;
    }

  /* find out which port scamper can be found listening on */
  if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
    {
      usage(OPT_PORT);
      return -1;
    }
  port = lo;

  if((options & OPT_PRIORITY) != 0)
    {
      if(string_tolong(opt_priority, &lo) != 0 || lo < 1)
	{
	  usage(OPT_PRIORITY);
	  return -1;
	}
      priority = lo;
    }

  return 0;
}

/*
 * do_infile
 *
 * read the contents of the infile in one hit.
 */
static int do_infile(void)
{
  struct stat sb;
  size_t off, start;
  char *readbuf = NULL;
  char *command;
  int fd = -1;

  if((commands = slist_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc commands list\n");
      return -1;
    }

  if(infile == NULL)
    {
      return 0;
    }

  if((fd = open(infile, O_RDONLY)) < 0)
    {
      fprintf(stderr, "could not open %s\n", infile);
      goto err;
    }

  if(fstat(fd, &sb) != 0)
    {
      fprintf(stderr, "could not fstat %s\n", infile);
      goto err;
    }
  if(sb.st_size == 0)
    {
      fprintf(stderr, "zero length file %s\n", infile);
      goto err;
    }
  if((readbuf = malloc(sb.st_size+1)) == NULL)
    {
      fprintf(stderr, "could not malloc %d bytes to read %s\n",
	      (int)sb.st_size, infile);
      goto err;
    }
  if(read_wrap(fd, readbuf, NULL, sb.st_size) != 0)
    {
      fprintf(stderr, "could not read %d bytes from %s\n",
	      (int)sb.st_size, infile);
      goto err;
    }
  readbuf[sb.st_size] = '\0';
  close(fd); fd = -1;

  /* parse the contents of the file */
  start = 0; off = 0;
  while(off < sb.st_size+1)
    {
      if(readbuf[off] == '\n' || readbuf[off] == '\0')
	{
	  if(start == off || readbuf[start] == '#')
	    {
	      start = ++off;
	      continue;
	    }

	  readbuf[off] = '\0';

	  if((command = malloc(off-start+2)) == NULL)
	    {
	      fprintf(stderr, "could not malloc command\n");
	      goto err;
	    }
	  memcpy(command, readbuf+start, off-start);
	  command[off-start+0] = '\n';
	  command[off-start+1] = '\0';

	  if(slist_tail_push(commands, command) == NULL)
	    {
	      fprintf(stderr, "could not push command onto list\n");
	      free(command);
	      goto err;
	    }

	  start = ++off;
	}
      else
	{
	  ++off;
	}
    }

  free(readbuf);
  return 0;

 err:
  if(readbuf != NULL) free(readbuf);
  if(fd != -1) close(fd);
  return -1;
}

/*
 * do_outfile
 *
 * open a file to send the binary warts data file to.
 */
static int do_outfile(void)
{
  mode_t mode   = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  int    flags  = O_WRONLY | O_CREAT | O_TRUNC;

  if(outfile_name == NULL)
    return 0;

  if((outfile_fd = open(outfile_name, flags, mode)) == -1)
    {
      fprintf(stderr, "could not open %s\n", outfile_name);
      return -1;
    }

  return 0;
}

/*
 * do_scamperconnect
 *
 * allocate socket and connect to scamper process listening on the port
 * specified.
 */
static int do_scamperconnect(void)
{
  struct sockaddr_in sin;
  struct in_addr in;

  in.s_addr = inet_addr("127.0.0.1");
  sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);

  if((scamper_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      fprintf(stderr, "could not allocate new socket\n");
      return -1;
    }

  if(connect(scamper_fd, (const struct sockaddr *)&sin, sizeof(sin)) != 0)
    {
      fprintf(stderr, "could not connect to scamper process\n");
      return -1;
    }

  return 0;
}

static int do_method(void)
{
  struct timeval tv;
  char *command;

  if(slist_count(commands) == 0)
    return 0;

  gettimeofday_wrap(&tv);
  command = slist_head_pop(commands);
  write_wrap(scamper_fd, command, NULL, strlen(command));
  more--;

  if((options & OPT_DEBUG) != 0)
    fprintf(stderr, "%ld: %s", (long int)tv.tv_sec, command);

  if(lastcommand != NULL)
    free(lastcommand);
  lastcommand = command;

  if(slist_count(commands) == 0 && stdin_fd == -1 && done == 0)
    {
      write_wrap(scamper_fd, "done\n", NULL, 5);
      done = 1;
    }

  return 0;
}

static int do_stdinread(void)
{
  ssize_t rc;
  char   *ptr, *head, *command;
  char    buf[512];
  void   *tmp;
  size_t  i, linelen;

  if((rc = read(stdin_fd, buf, sizeof(buf))) > 0)
    {
      if(stdinbuf_len == 0)
	{
	  if((stdinbuf = memdup(buf, rc)) == NULL)
	    {
	      return -1;
	    }
	  stdinbuf_len = rc;
	}
      else
	{
	  if((tmp = realloc(stdinbuf, stdinbuf_len + rc)) != NULL)
	    {
	      stdinbuf = tmp;
	      memcpy(stdinbuf+stdinbuf_len, buf, rc);
	      stdinbuf_len += rc;
	    }
	  else return -1;
	}
    }
  else if(rc == 0)
    {
      if(done == 0)
	write_wrap(scamper_fd, "done\n", NULL, 5);
      done = 1;
      stdin_fd = -1;
      return 0;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }
  else
    {
      fprintf(stderr, "could not read: errno %d\n", errno);
      return -1;
    }

  /* process whatever is in the stdinbuf */
  if(stdinbuf_len == 0)
    {
      goto done;
    }

  head = stdinbuf;
  for(i=0; i<stdinbuf_len; i++)
    {
      if(stdinbuf[i] != '\n')
	continue;

      /* calculate the length of the line, including newline */
      linelen = &stdinbuf[i] - head + 1;

      /* skip empty lines */
      if(linelen == 1 || head[0] == '#')
	{
	  head = &stdinbuf[i+1];
	  continue;
	}

      /* make a copy of the command string */
      if((command = malloc(linelen+1)) == NULL)
	{
	  fprintf(stderr, "could not malloc command\n");
	  goto err;
	}
      memcpy(command, head, linelen);
      command[linelen] = '\0';

      /* put the command string on the list of things to do */
      if(slist_tail_push(commands, command) == NULL)
	{
	  fprintf(stderr, "could not push command onto list\n");
	  free(command);
	  goto err;
	}

      head = &stdinbuf[i+1];
    }

  if(head != &stdinbuf[stdinbuf_len])
    {
      stdinbuf_len = &stdinbuf[stdinbuf_len] - head;
      ptr = memdup(head, stdinbuf_len);
      free(stdinbuf);
      stdinbuf = ptr;
    }
  else
    {
      stdinbuf_len = 0;
      free(stdinbuf);
      stdinbuf = NULL;
    }

 done:
  return 0;

 err:
  return -1;
}

/*
 * do_scamperread
 *
 * the fd for the scamper process is marked as readable, so do a read
 * on it.
 */
static int do_scamperread(void)
{
  ssize_t rc;
  uint8_t uu[64];
  char   *ptr, *head;
  char    buf[512];
  void   *tmp;
  long    l;
  size_t  i, uus, linelen;

  if((rc = read(scamper_fd, buf, sizeof(buf))) > 0)
    {
      if(readbuf_len == 0)
	{
	  if((readbuf = memdup(buf, rc)) == NULL)
	    {
	      return -1;
	    }
	  readbuf_len = rc;
	}
      else
	{
	  if((tmp = realloc(readbuf, readbuf_len + rc)) != NULL)
	    {
	      readbuf = tmp;
	      memcpy(readbuf+readbuf_len, buf, rc);
	      readbuf_len += rc;
	    }
	  else return -1;
	}
    }
  else if(rc == 0)
    {
      close(scamper_fd);
      scamper_fd = -1;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }
  else
    {
      fprintf(stderr, "could not read: errno %d\n", errno);
      return -1;
    }

  /* process whatever is in the readbuf */
  if(readbuf_len == 0)
    {
      goto done;
    }

  head = readbuf;
  for(i=0; i<readbuf_len; i++)
    {
      if(readbuf[i] != '\n')
	continue;

      /* skip empty lines */
      if(head == &readbuf[i])
	{
	  head = &readbuf[i+1];
	  continue;
	}

      /* calculate the length of the line, excluding newline */
      linelen = &readbuf[i] - head;

      /* if currently decoding data, then pass it to uudecode */
      if(data_left > 0)
	{
	  uus = sizeof(uu);
	  if(uudecode_line(head, linelen, uu, &uus) != 0)
	    {
	      fprintf(stderr, "could not uudecode_line\n");
	      goto err;
	    }

	  if(uus != 0)
	    {
	      if(outfile_fd != -1)
		write_wrap(outfile_fd, uu, NULL, uus);
	      if(options & OPT_STDOUT)
		write_wrap(STDOUT_FILENO, uu, NULL, uus);
	    }

	  data_left -= (linelen + 1);
	}
      /* if the scamper process is asking for more tasks, give it more */
      else if(linelen == 4 && strncasecmp(head, "MORE", linelen) == 0)
	{
	  more++;
	}
      /* new piece of data */
      else if(linelen > 5 && strncasecmp(head, "DATA ", 5) == 0)
	{
	  l = strtol(head+5, &ptr, 10);
	  if(*ptr != '\n' || l < 1)
	    {
	      head[linelen] = '\0';
	      fprintf(stderr, "could not parse %s\n", head);
	      goto err;
	    }

	  data_left = l;
	}
      /* feedback letting us know that the command was accepted */
      else if(linelen >= 2 && strncasecmp(head, "OK", 2) == 0)
	{
	  /* err, nothing to do */
	}
      /* feedback letting us know that the command was not accepted */
      else if(linelen >= 3 && strncasecmp(head, "ERR", 3) == 0)
	{
	  if(lastcommand != NULL)
	    {
	      fprintf(stderr, "command not accepted: %s", lastcommand);
	      more++;
	    }
	  else
	    {
	      goto err;
	    }
	}
      else
	{
	  head[linelen] = '\0';
	  fprintf(stderr, "unknown response '%s'\n", head);
	  goto err;
	}

      head = &readbuf[i+1];
    }

  if(head != &readbuf[readbuf_len])
    {
      readbuf_len = &readbuf[readbuf_len] - head;
      ptr = memdup(head, readbuf_len);
      free(readbuf);
      readbuf = ptr;
    }
  else
    {
      readbuf_len = 0;
      free(readbuf);
      readbuf = NULL;
    }

 done:
  return 0;

 err:
  return -1;
}

static int do_attach(void)
{
  char buf[256];
  size_t off = 0;

  string_concat(buf, sizeof(buf), &off, "attach");
  if((options & OPT_PRIORITY) != 0)
    string_concat(buf, sizeof(buf), &off, " priority %d", priority);
  string_concat(buf, sizeof(buf), &off, "\n");

  if(write_wrap(scamper_fd, buf, NULL, off) != 0)
    {
      fprintf(stderr, "could not attach to scamper process\n");
      return -1;
    }

  return 0;
}

int main(int argc, char *argv[])
{
  fd_set rfds;
  int nfds;

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  /*
   * read the list of addresses in the address list file.
   */
  if(do_infile() != 0)
    return -1;

  /*
   * connect to the scamper process
   */
  if(do_scamperconnect() != 0)
    return -1;

  if(do_outfile() != 0)
    return -1;

  /* attach */
  if(do_attach() != 0)
    return -1;

  for(;;)
    {
      if(scamper_fd == -1)
	{
	  break;
	}

      nfds = 0;
      FD_ZERO(&rfds);

      /* will always read the scamper process */
      FD_SET(scamper_fd, &rfds);
      if(nfds < scamper_fd)
	nfds = scamper_fd;

      /* might read commands from stdin */
      if(stdin_fd != -1)
	{
	  FD_SET(stdin_fd, &rfds);
	  if(nfds < stdin_fd)
	    nfds = stdin_fd;
	}

      if(more > 0)
	{
	  do_method();
	}

      if(select(nfds+1, &rfds, NULL, NULL, NULL) < 0)
	{
	  if(errno == EINTR) continue;
	  break;
	}

      if(stdin_fd != -1 && FD_ISSET(stdin_fd, &rfds))
	{
	  if(do_stdinread() != 0)
	    return -1;
	}

      if(FD_ISSET(scamper_fd, &rfds))
	{
	  if(do_scamperread() != 0)
	    return -1;
	}
    }

  return 0;
}
