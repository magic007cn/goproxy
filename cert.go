package main;

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"
)

type CertificateManager struct {
    certFile    string
    keyFile     string
    cert        *tls.Certificate
    lastModTime time.Time
    mu          sync.RWMutex
}

func NewCertificateManager(certFile, keyFile string) (*CertificateManager, error) {
    cm := &CertificateManager{
        certFile: certFile,
        keyFile:  keyFile,
    }
    if err := cm.reload(); err != nil {
        return nil, err
    }
    return cm, nil
}

func (cm *CertificateManager) reload() error {
    cert, err := tls.LoadX509KeyPair(cm.certFile, cm.keyFile)
    if err != nil {
        return err
    }

    cm.mu.Lock()
    defer cm.mu.Unlock()
    cm.cert = &cert
    cm.lastModTime = time.Now()
    return nil
}

func (cm *CertificateManager) GetCertificate() *tls.Certificate {
    cm.mu.RLock()
    defer cm.mu.RUnlock()
    return cm.cert
}

func (cm *CertificateManager) WatchChanges() {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        info, err := os.Stat(cm.certFile)
        if err != nil {
            log.Printf("Failed to stat cert file: %v", err)
            continue
        }
        
        if info.ModTime().After(cm.lastModTime) {
            if err := cm.reload(); err != nil {
                log.Printf("Failed to reload certificate: %v", err)
            } else {
                log.Println("Successfully reloaded certificate")
            }
        }
    }
}