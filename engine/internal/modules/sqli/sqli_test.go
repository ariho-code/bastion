package sqli

import "testing"

func TestMatchDBErrorPrecision(t *testing.T) {
	if matchDBError("hello world") != "" {
		t.Fatal("generic body must not match")
	}
	if matchDBError("You have an error in your SQL syntax; check the manual") == "" {
		t.Fatal("mysql syntax error must match")
	}
	if matchDBError("org.postgresql.util.PSQLException: ERROR: syntax error at or near") == "" {
		t.Fatal("postgres error must match")
	}
	// Docs mentioning SQL should not trip generic words alone
	if matchDBError("This page explains SQL injection and prepared statements") != "" {
		t.Fatal("educational content without error fingerprint must not match")
	}
}
