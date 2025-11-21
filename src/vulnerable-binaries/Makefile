# Copyright 2025 Alex Vong
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CPPFLAGS = -D_FORTIFY_SOURCE=2
CFLAGS = -Wall -Wextra -pedantic -Ofast -foptimize-sibling-calls -fstack-protector-all -fsanitize=undefined
LDFLAGS = -Wl,-z,now

.PHONY: all

all: display-csv display-json

display-csv: display-csv.c
	gcc -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $?

display-json: display-json.c
	gcc -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $?

clean:
	rm -f display-csv display-json
