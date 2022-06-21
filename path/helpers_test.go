// Licensed to zntr.io under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. zntr.io licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package path

import "testing"

func TestSanitizePath(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "blank",
			args: args{
				s: "",
			},
			want: "",
		},
		{
			name: "whitespace prefixed",
			args: args{
				s: "  app/foo",
			},
			want: "app/foo",
		},
		{
			name: "whitespace suffixed",
			args: args{
				s: "app/foo   ",
			},
			want: "app/foo",
		},
		{
			name: "slash suffixed",
			args: args{
				s: "app/foo/",
			},
			want: "app/foo",
		},
		{
			name: "slash prefixed",
			args: args{
				s: "/app/foo",
			},
			want: "app/foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizePath(tt.args.s); got != tt.want {
				t.Errorf("SanitizePath() = %v, want %v", got, tt.want)
			}
		})
	}
}
