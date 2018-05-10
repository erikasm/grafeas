// Copyright 2017 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"testing"

	server "github.com/grafeas/grafeas/server-go"
)

func TestPgSQLJsonbStore(t *testing.T) {
	createPgSQLJsonbStore := func(t *testing.T) (server.Storager, func()) {
		t.Helper()
		config := &PgSQLConfig{
			Host:          "127.0.0.1:5432",
			DbName:        "test_db",
			User:          "postgres",
			Password:      "password",
			SSLMode:       "disable",
			PaginationKey: "XxoPtCUzrUv4JV5dS+yQ+MdW7yLEJnRMwigVY/bpgtQ=",
		}
		pg := NewPgSQLJsonbStore(config)
		return pg, func() { dropDatabase(t, config); pg.Close() }
	}

	doTestStorager(t, createPgSQLJsonbStore)
}
