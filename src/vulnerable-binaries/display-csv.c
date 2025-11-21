/* This program parses csv (with no support for quotation) as s-expression
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

typedef struct list
{
  char type;
  void *first;
  struct list *rest;
} list;

struct list *EMPTY = NULL;

static list *cons(void *first, list *rest)
{
  list *ls = calloc(1, sizeof(list));
  ls->first = first;
  ls->rest = rest;
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

static list *string_to_row_recur(list *acc)
{
  char *x = strtok(NULL, ",");
  if (!x)
    return acc;
  else
    return string_to_row_recur(cons(x, acc));
}

static list *string_to_row(char* s)
{
  char *x = strtok(s, ",");
  if (!x)
    return EMPTY;
  else
    return string_to_row_recur(cons(x, EMPTY));
}

static list *read_as_csv_recur(list *acc)
{
  char *line = NULL;
  size_t len = 0;

  int r = getline(&line, &len, stdin);
  line[strlen(line) - 1] = '\0'; // VULN: array out of bound

  list *row = reverse(string_to_row(line));

  if (r < 0)
    return acc;
  else
    return read_as_csv_recur(cons(row, acc));
}

static list *read_as_csv()
{
  return reverse(read_as_csv_recur(EMPTY));
}

static void display_string_list_recur(list *ls)
{
  if (ls)
    {
      printf((char *)(ls->first)); // VULN: format string

      if (ls->rest)
        printf(" ");

      display_string_list_recur(ls->rest);
    }
}

static void display_string_list(list *ls)
{
  printf("(");
  display_string_list_recur(ls);
  printf(")");
}

static void display_csv_recur(list *ls)
{
  if (ls)
    {
      display_string_list(ls->first);

      if (ls->rest)
        printf(" ");

      display_csv_recur(ls->rest);
    }
}

static void display_csv(list *ls)
{
  printf("(");
  display_csv_recur(ls);
  printf(")");
}

int main(void)
{
  list *csv = read_as_csv();
  display_csv(csv);
  puts("");
  return 0;
}
