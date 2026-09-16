package main

import (
	"errors"
	"io"
	"testing"
)

func TestInstallTransferInterruptIsUnconfirmed(t *testing.T) {
	code, message, status := classifyInstallTransferError(io.EOF)
	if code != "install_unconfirmed" || status != "unknown" || message == "" {
		t.Fatalf("eof should be unconfirmed, got %s %s %s", code, status, message)
	}
	code, message, status = classifyInstallTransferError(errors.New("connection reset by peer"))
	if code != "install_unconfirmed" || status != "unknown" {
		t.Fatalf("reset should be unconfirmed, got %s %s", code, status)
	}
	code, _, status = classifyInstallTransferError(errors.New("zipconduit rejected package"))
	if code != "install_failed" || status != "failed" {
		t.Fatalf("generic failure should stay install_failed, got %s %s", code, status)
	}
	code, _ = classifyInstallConnectError(errors.New("could not start com.apple.streaming_zip_conduit"))
	if code != "install_service_unavailable" {
		t.Fatalf("service start failure should stay unavailable, got %s", code)
	}
}
