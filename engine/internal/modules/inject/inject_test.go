package inject

import "testing"

func TestPasswdFingerprint(t *testing.T) {
	if looksLikePasswd("root is the superuser") {
		t.Fatal("mention of root must not match")
	}
	if !looksLikePasswd("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n") {
		t.Fatal("real passwd content must match")
	}
	if !looksLikeWinINI("[fonts]\n[extensions]\n") {
		t.Fatal("win.ini fingerprint")
	}
}
