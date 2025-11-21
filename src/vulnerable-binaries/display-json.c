/* This program parses (a proper subset of) json as s-expression
   (see https://en.wikipedia.org/wiki/S-expression) and display it.

   Search for VULN for vulnerabilities.

   Copyright 2025 Alex Vong

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. */

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define fail_to_read(c)                                 \
  do                                                    \
    {                                                   \
      fprintf(stderr, "unexpected token: %c\n", (c));   \
      exit(EXIT_FAILURE);                               \
    }                                                   \
  while (0)

#define expect(s)                                       \
  do                                                    \
    {                                                   \
      fprintf(stderr, "expect one of: %s\n", (s));      \
      exit(EXIT_FAILURE);                               \
    }                                                   \
  while (0)

typedef struct list
{
  char type;
  void *first;
  struct list *rest;
} list;

static list *read_json(void);
static void display_json(list *json);

struct list *EMPTY = NULL;

static list *cons(void *first, list *rest)
{
  list *ls = calloc(1, sizeof(list));
  ls->first = first;
  ls->rest = rest;
  return ls;
}

static list *make_number(int64_t first, list *rest)
{
  list *ls = cons((void *)first, rest);
  ls->type = 'n';
  return ls;
}

static list *make_string(char *first, list *rest)
{
  list *ls = cons(first, rest);
  ls->type = 's';
  return ls;
}

static list *reverse_recur(list* acc, list *ls)
{
  if (!ls)
    return acc;
  else
    return reverse_recur(cons(ls->first, acc), ls->rest);
}

static list *reverse(list *ls)
{
  return reverse_recur(EMPTY, ls);
}

static void skip_spaces(void)
{
  int c = getchar();

  if (c == EOF)
    return;
  else if (isspace(c))
    skip_spaces();
  else
    ungetc(c, stdin);
}

static int64_t read_number_recur(int64_t acc)
{
  int c = getchar();

  if (c == EOF)
    {
      return acc;
    }
  else if (isdigit(c))
    {
      int64_t d = c - 0x30;
      return read_number_recur(acc * 10 + d); // VULN: integer overflow
    }
  else
    {
      ungetc(c, stdin);
      return acc;
    }
}

static list *read_number(void)
{
  return make_number(read_number_recur(0), EMPTY);
}

static char *read_string_recur(char *buf, size_t buf_size, size_t j)
{
  int c = getchar();

  if (c == EOF)
    {
      expect("\"");
    }
  else if (j >= buf_size)
    {
      ungetc(c, stdin);
      size_t new_buf_size = buf_size * 2; // VULN: integer overflow
      char *new_buf = realloc(buf, new_buf_size);
      return read_string_recur(new_buf, new_buf_size, j);
    }
  else if (c == '"')
    {
      buf[j] = '\0';
      return buf;
    }
  else
    {
      buf[j] = c;
      return read_string_recur(buf, buf_size, j + 1);
    }
}

static list *read_string(void)
{
  char *buf = calloc(1, 1);
  size_t buf_size = 1;

  getchar();
  char *s = read_string_recur(buf, buf_size, 0);
  return make_string(s, EMPTY);
}

static list *read_list_recur(list *acc)
{
  skip_spaces();

  int c = getchar();
  if (c == EOF)
    {
      expect("]");
    }
  else if (c == ']')
    {
      return acc;
    }
  else
    {
      ungetc(c, stdin);

      list *x = read_json();

      skip_spaces();
      int c2 = getchar();
      if (c2 == ',')
        {
          skip_spaces();
          int c3 = getchar();

          if (isdigit(c) || c3 == '"' || c3 == '[' || c3 == '{')
            ungetc(c3, stdin);
          else
            expect("0123456789\"[{");

          return read_list_recur(cons(x, acc));
        }
      else if (c2 == ']')
        {
          ungetc(c2, stdin);
          return read_list_recur(cons(x, acc));
        }
      else
        {
          expect(",]");
        }
    }
}

static list *read_list(void)
{
  getchar();
  return reverse(read_list_recur(EMPTY));
}

static list *read_pair(void)
{
  list *k = read_json();

  skip_spaces();

  int c = getchar();
  if (c != ':')
    expect(":");

  list *v = read_json();

  return cons(k, cons(v, EMPTY));
}

static list *read_mapping_recur(list *acc)
{
  skip_spaces();

  int c = getchar();
  if (c == EOF)
    {
      expect("}");
    }
  else if (c == '}')
    {
      return acc;
    }
  else
    {
      ungetc(c, stdin);

      list *pair = read_pair();

      skip_spaces();
      int c2 = getchar();
      if (c2 == ',')
        {
          skip_spaces();
          int c3 = getchar();

          if (isdigit(c) || c3 == '"' || c3 == '[' || c3 == '{')
            ungetc(c3, stdin);
          else
            expect("0123456789\"[{");

          return read_mapping_recur(cons(pair, acc));
        }
      else if (c2 == '}')
        {
          ungetc(c2, stdin);
          return read_mapping_recur(cons(pair, acc));
        }
      else
        {
          expect(",}");
        }
    }
}

static list *read_mapping(void)
{
  getchar();
  return reverse(read_mapping_recur(EMPTY));
}

static void display_number(list *ls)
{
  printf("%" PRId64, (int64_t)(ls->first));
}

static void display_character(char *s, size_t len)
{
  if (len > 0)
    {
      printf("%c", s[0]);
      display_character(s + 1, len - 1);
    }
}

static void display_string(list *ls)
{
  char *s = ls->first;
  size_t len = strlen(ls->first);
  printf("\"");
  display_character(s, len);
  printf("\"");
}

static void display_list_recur(list *ls)
{
  if (ls)
    {
      display_json(ls->first);

      if (ls->rest)
        printf(" ");

      display_list_recur(ls->rest);
    }
}

static void display_list(list *ls)
{
  printf("(");
  display_list_recur(ls);
  printf(")");
}

static void display_json(list *ls)
{
  if (!ls)
    display_list(ls);
  else if (ls->type == 'n')
    display_number(ls);
  else if (ls->type == 's')
    display_string(ls);
  else
    display_list(ls);
}

static list *read_json(void)
{
  skip_spaces();

  int c = getchar();

  if (c != EOF)
    ungetc(c, stdin);

  if (c == EOF)
    return EMPTY;
  else if (isdigit(c))
    return read_number();
  else if (c == '"')
    return read_string();
  else if (c == '[')
    return read_list();
  else if (c == '{')
    return read_mapping();
  else
    fail_to_read(c);
}

int main(void)
{
  list *json = read_json();
  display_json(json);
  puts("");
  return 0;
}
