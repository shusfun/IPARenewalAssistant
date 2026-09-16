package main
import (
  "context"
  "os"
  "testing"
  "time"
)
func TestLiveSignCurrentApp(t *testing.T) {
  if os.Getenv("LIVE_SIGN") != "1" { t.Skip() }
  paths, err := defaultPaths(); if err != nil { t.Fatal(err) }
  events := acceptanceEvents{finished: make(chan JobFinished, 2), log: t.Logf}
  service, err := NewService(paths, RealCommandRunner{}, events); if err != nil { t.Fatal(err) }
  if !service.GetAppleAccountStatus().SignedIn { t.Fatal("not signed in") }
  state := service.store.Snapshot()
  var appID string
  for id := range state.Apps { appID = id; break }
  if appID == "" { t.Fatal("no app") }
  devices, err := service.ListDevices(context.Background()); if err != nil { t.Fatal(err) }
  if len(devices) == 0 { t.Fatal("no device") }
  if _, err := service.SignApp(appID, devices[0].ID, "preserve"); err != nil { t.Fatal(err) }
  select {
  case r := <-events.finished:
    if !r.Success { t.Fatalf("code=%s msg=%s", r.Code, r.Message) }
    t.Log("sign_ok")
  case <-time.After(12 * time.Minute):
    t.Fatal("timeout")
  }
}
